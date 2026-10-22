"""Isolated finite checks: no real controls, perf, sudo or child launches."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import perf_sampling_probe as probe


PID = 1234
EXE = "/usr/bin/python3.12"


def record(kind, body=b"", misc=0):
    body += b"\0" * ((-len(body)) % 8)
    return struct.pack("<IHH", kind, misc, len(body) + 8) + body


def sample(mode=2, pid=PID, period=probe.PERIOD_NS, chain=(0x1234,)):
    return record(9, struct.pack("<QIIQQQ", 0x1234, pid, pid, 123456789, period, len(chain))
                  + struct.pack("<" + "Q" * len(chain), *chain), mode)


def mapping():
    body = bytearray(64)
    struct.pack_into("<II", body, 0, PID, PID)
    return record(10, bytes(body) + EXE.encode() + b"\0", 2)


def capture(records=None, event="cpu-clock", ids=(101, 102), trailer=False, feature=None):
    records = mapping() + sample() if records is None else records
    header = bytearray(104)
    header[:8] = b"PERFILE2"
    ids_raw = struct.pack("<" + "Q" * len(ids), *ids)
    ao, az = 104 + len(ids_raw), 160
    do = ao + az
    struct.pack_into("<8Q", header, 8, 104, az, ao, az, do, len(records), 0, 0)
    attr = bytearray(160)
    flags = (1 << 10) | ((1 << 18) if trailer else 0)
    struct.pack_into("<II5Q", attr, 0, 1, 144, 0 if event == "cpu-clock" else 1,
                     997, 295, 20, flags)
    struct.pack_into("<QQ", attr, 144, 104, len(ids_raw))
    footer = b""
    if feature is not None:
        header[72] = 4
        footer = struct.pack("<QQ", do + len(records) + 16, len(feature)) + feature
    return bytes(header) + ids_raw + bytes(attr) + records + footer


def receipt(pattern="continuous", **changes):
    value = {"schema": 1, "pid": PID, "pattern": pattern, "process_cpu_ns": 500_050_000,
             "thread_cpu_ns": 500_000_000, "wall_ns": 600_000_000,
             "iterations": 10_000, "blocks": 1000, "max_block_cpu_ns": 60_000,
             "blocks_at_or_above_period": 0, "sleep_calls": 999 if pattern == "bursty" else 0,
             "voluntary_context_switches": 999 if pattern == "bursty" else 0,
             "involuntary_context_switches": 3, "completed": True, "deadline_hit": False,
             "block_limit_hit": False, "short_blocks_valid": True}
    value.update(changes)
    return value


class FakeClocks:
    def __init__(self, cpu_step=25_000, wall_step=5_000):
        self.cpu_ns = 0
        self.wall_ns = 0
        self.cpu_step = cpu_step
        self.wall_step = wall_step
        self.sleeps = 0

    def cpu(self):
        self.cpu_ns += self.cpu_step
        self.wall_ns += self.cpu_step
        return self.cpu_ns

    def thread(self):
        return self.cpu_ns

    def wall(self):
        self.wall_ns += self.wall_step
        return self.wall_ns

    def sleep(self, seconds):
        self.sleeps += 1
        self.wall_ns += round(seconds * 1e9)

    def usage(self):
        return SimpleNamespace(ru_nvcsw=self.sleeps, ru_nivcsw=0)

    def measure(self, pattern):
        return probe.measure_control(pattern, cpu=self.cpu, thread=self.thread, wall=self.wall,
                                     sleep=self.sleep, usage=self.usage)


class WorkerTests(unittest.TestCase):
    def test_bounded_pipe_parser_faults_without_real_pipe(self):
        for pieces, limit, error in (([b"x", b""], 16, EOFError), ([b"x"] * 5, 4, ValueError)):
            with patch.object(probe.select, "select", return_value=([123], [], [])), \
                 patch.object(probe.os, "read", side_effect=pieces), self.assertRaises(error):
                probe.read_line(123, time.monotonic() + 1, limit)
        with patch.object(probe.select, "select", return_value=([], [], [])), self.assertRaises(TimeoutError):
            probe.read_line(123, time.monotonic() + 1)

    def test_partial_gate_is_not_retried(self):
        with patch.object(probe.select, "select", return_value=([], [123], [])), \
             patch.object(probe.os, "write", return_value=1) as write, self.assertRaisesRegex(ValueError, "not retried"):
            probe.write_gate(123, b"run\n", time.monotonic() + 1)
        write.assert_called_once()

    def test_target_includes_clock_and_loop_overhead_not_just_blocks(self):
        clocks = FakeClocks()
        result = clocks.measure("continuous")
        self.assertTrue(result["completed"])
        self.assertFalse(result["deadline_hit"])
        self.assertLess(result["blocks"] * result["max_block_cpu_ns"], probe.TARGET_CPU_NS)
        self.assertEqual(result["sleep_calls"], 0)
        self.assertLessEqual(len(probe.bounded_bytes(result, 1024)), 1024)
        probe.validate_receipt(result, os.getpid(), "continuous")

    def test_bursty_sleep_is_finite_and_condition_measured(self):
        result = FakeClocks().measure("bursty")
        probe.validate_receipt(result, os.getpid(), "bursty")
        self.assertEqual(result["sleep_calls"], result["blocks"] - 1)
        self.assertGreater(result["voluntary_context_switches"], 0)

    def test_wall_deadline_does_not_extend_for_cpu_target(self):
        result = FakeClocks(wall_step=500_000_000).measure("bursty")
        self.assertTrue(result["deadline_hit"])
        self.assertFalse(result["completed"])
        self.assertLess(result["blocks"], 10000)
        with self.assertRaisesRegex(ValueError, "target, finite bound"):
            probe.validate_receipt(result, os.getpid(), "bursty")

    def test_block_cap_does_not_extend(self):
        with patch.object(probe, "MAX_BLOCKS", 2):
            result = FakeClocks().measure("continuous")
        self.assertEqual(result["blocks"], 2)
        self.assertTrue(result["block_limit_hit"])
        self.assertFalse(result["completed"])

    def test_long_measured_block_invalidates_short_burst(self):
        result = FakeClocks(cpu_step=2_000_000).measure("bursty")
        self.assertFalse(result["short_blocks_valid"])
        self.assertGreater(result["blocks_at_or_above_period"], 0)
        with self.assertRaises(ValueError):
            probe.validate_receipt(result, os.getpid(), "bursty")

    def test_receipt_rejects_inconsistent_counts_and_identity(self):
        for changes in ({"pid": 999}, {"blocks": 10001}, {"completed": False},
                        {"process_cpu_ns": True}, {"max_block_cpu_ns": probe.PERIOD_NS},
                        {"short_blocks_valid": False}, {"pattern": "arbitrary"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                probe.validate_receipt(receipt(**changes), PID, "continuous")

    def test_continuous_cannot_hide_sleeps_and_bursty_cannot_omit_them(self):
        for pattern, changes in (("continuous", {"sleep_calls": 1}), ("bursty", {"sleep_calls": 0})):
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                probe.validate_receipt(receipt(pattern, **changes), PID, pattern)

    def test_json_only_after_report_gate(self):
        events = []
        result = receipt()
        with patch.object(probe.sys, "platform", "linux"), \
             patch.object(probe.os, "set_blocking"), \
             patch.object(probe, "read_line", side_effect=lambda *a: events.append("read") or (b"run\n" if events.count("read") == 1 else b"report\n")), \
             patch.object(probe, "write_gate", side_effect=lambda fd, gate, dl: events.append(gate)), \
             patch.object(probe, "measure_control", side_effect=lambda p: events.append("measure") or result), \
             patch.object(probe, "bounded_bytes", side_effect=lambda *a: events.append("format") or b"{}\n"), \
             patch.object(probe.select, "select", return_value=([], [1], [])), \
             patch.object(probe.os, "write", return_value=3), \
             patch.object(probe.sys, "stdin", Mock(fileno=lambda: 0)), \
             patch.object(probe.sys, "stdout", Mock(fileno=lambda: 1)):
            probe.worker_main("continuous")
        self.assertEqual(events, [b"ready\n", "read", "measure", b"measured\n", "read", "format"])


class RawParserTests(unittest.TestCase):
    def parse(self, data, event="cpu-clock"):
        return probe.parse_perf(data, event, PID, EXE)

    def test_inclusive_counts_modes_periods_and_mapping(self):
        data = capture(mapping() + sample(2) + sample(1) + sample(0) + sample(3))
        result = self.parse(data)
        self.assertEqual(result["sample_records"], 4)
        self.assertEqual(result["total_period"], 4 * probe.PERIOD_NS)
        self.assertEqual(result["samples_by_mode"]["unknown"], 1)
        self.assertEqual(result["samples_by_mode"]["kernel"], 1)
        self.assertEqual(result["event_id_count"], 2)
        self.assertTrue(result["executable_mapping_matches"])
        self.assertNotIn("symbols", result)

    def test_task_clock_is_distinct_config(self):
        data = capture(event="task-clock")
        self.assertEqual(self.parse(data, "task-clock")["event"], "task-clock")
        with self.assertRaisesRegex(ValueError, "unsupported event"):
            self.parse(data)

    def test_loss_and_throttle_with_sample_id_all(self):
        trailer = struct.pack("<IIQ", PID, PID, 123456)
        records = record(2, struct.pack("<QQ", 102, 7) + trailer)
        records += record(13, struct.pack("<Q", 3) + trailer)
        records += record(5, struct.pack("<QQQ", 123456, 101, 101) + trailer)
        records += record(6, struct.pack("<QQQ", 123457, 101, 101) + trailer)
        result = self.parse(capture(records, trailer=True))
        self.assertEqual((result["lost"], result["lost_samples"], result["throttle_records"], result["unthrottle_records"]), (7, 3, 1, 1))

    def test_feature_ranges_checked(self):
        data = capture(feature=b"metadata")
        self.assertEqual(self.parse(data)["sample_records"], 1)
        bad = bytearray(data)
        do, dz = struct.unpack_from("<QQ", data, 40)
        struct.pack_into("<Q", bad, do + dz, len(data) + 1)
        with self.assertRaisesRegex(ValueError, "out-of-bounds"):
            self.parse(bad)

    def test_unsupported_compressed_and_future_features_refused(self):
        for bit in (0, 24, 27, 100):
            data = bytearray(capture())
            data[72 + bit // 8] |= 1 << (bit % 8)
            with self.subTest(bit=bit), self.assertRaisesRegex(ValueError, "unsupported reserved"):
                self.parse(data)

    def test_header_truncation_and_sections_refused(self):
        good = capture()
        variants = [good[:103], b"2ELIFREP" + good[8:], good[:-1], good + b"x" * probe.QUOTA]
        for position, value in ((8, 105), (24, len(good)), (32, 320), (40, 104), (48, len(good) * 2)):
            bad = bytearray(good)
            struct.pack_into("<Q", bad, position, value)
            variants.append(bad)
        for data in variants:
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                self.parse(data)

    def test_wrong_frequency_scope_and_layout_refused(self):
        for position, value in ((8, 2), (16, 998), (24, 295 | 64), (32, 0), (40, (1 << 10) | (1 << 5))):
            data = bytearray(capture())
            ao = struct.unpack_from("<Q", data, 24)[0]
            struct.pack_into("<Q", data, ao + position, value)
            with self.subTest(position=position), self.assertRaises(ValueError):
                self.parse(data)

    def test_pid_callchain_record_size_and_unknown_types_refused(self):
        variants = [capture(sample(pid=PID + 1)), capture(record(81)), capture(record(999)),
                    capture(sample(mode=6)), capture(sample(period=0)),
                    capture(record(9, struct.pack("<QIIQQQ", 1, PID, PID, 5, 1, 999999)))]
        bad = bytearray(capture(sample()))
        do = struct.unpack_from("<Q", bad, 40)[0]
        struct.pack_into("<H", bad, do + 6, 0)
        variants.append(bad)
        for data in variants:
            with self.subTest(data=data[-16:]), self.assertRaises(ValueError):
                self.parse(data)

    def test_duplicate_event_ids_and_wrong_throttle_size_refused(self):
        for data in (capture(ids=(101, 101)), capture(record(5, b"x" * 8))):
            with self.assertRaises(ValueError):
                self.parse(data)

    def test_known_opaque_metadata_is_counted_not_decoded(self):
        result = self.parse(capture(record(82) + sample()))
        self.assertEqual(result["records_by_type"]["82"], 1)
        self.assertEqual(result["sample_records"], 1)

    def test_loss_id_not_in_event_table_refused(self):
        with self.assertRaisesRegex(ValueError, "event ID mismatch"):
            self.parse(capture(record(2, struct.pack("<QQ", 999, 7))))

    def test_mapping_unterminated_refused(self):
        for body in (struct.pack("<II", PID, PID) + b"x" * 8,):
            with self.assertRaises(ValueError):
                self.parse(capture(record(3, body)))


    def test_perf_self_metadata_not_misattributed_to_target(self):
        data = capture(record(3, struct.pack("<II", PID + 1, PID + 1) + b"perf-exec\0") + mapping() + sample())
        result = self.parse(data)
        self.assertEqual(result["foreign_userspace_metadata_records"], 1)
        self.assertEqual(result["sample_records"], 1)
        self.assertTrue(result["executable_mapping_matches"])


class WorkflowTests(unittest.TestCase):
    def test_manual_pinned_bounded_existing_runner_transport(self):
        text = (probe.SUITE / ".github/workflows/perf-sampling-probe.yml").read_text()
        self.assertIn("on:\n  workflow_dispatch:\n", text)
        self.assertNotIn("pull_request", text)
        self.assertNotIn("push:", text)
        self.assertIn("permissions:\n  contents: read\n", text)
        self.assertIn("group: manual-linux-cpu\n  cancel-in-progress: false", text)
        self.assertIn("runs-on: ubuntu-24.04", text)
        self.assertIn("timeout-minutes: 10", text)
        self.assertIn("ulimit -f 4096\n", text)
        for module in ("test_linux_cpu.RecordControlTests", "test_linux_cpu.RecordFifoTests",
                       "test_linux_cpu.LinuxProcessTests", "test_perf_sampling_probe"):
            self.assertIn(module + " \\\n", text)
        self.assertIn("PYTHONPATH=tools/benchmark timeout", text)
        self.assertIn("--kill-after=5 90", text)
        self.assertEqual(probe.TEST_LOG_LIMIT, 4 * 1024 * 1024)
        self.assertLessEqual(4 * 3 * probe.QUOTA + 32 * probe.META_LIMIT + probe.TEST_LOG_LIMIT, probe.OUTPUT_LIMIT)
        self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("if: always()", text)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", text)
        self.assertIn("retention-days: 14", text)
        self.assertIn('--output "$RUNNER_TEMP/perf-sampling-probe-evidence/controls"', text)
        self.assertLess(text.index("-m unittest"), text.index("python3 -B tools/benchmark/perf_sampling_probe.py"))
        for forbidden in ("apt-get", "pip install", "cargo ", "rustup", "sysctl", "sudoers", "eBPF"):
            self.assertNotIn(forbidden, text)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def control(self, *, fail_enter=False, fail_finish=False, fail_cleanup=False, bad_receipt=False, bad_header=False, bad_deadline=False, startup_cleanup_failure=False):
        events = []
        stdin, stdout = Mock(), Mock()
        stdin.fileno.return_value, stdout.fileno.return_value = 101, 102
        worker = Mock(pid=PID, stdin=stdin, stdout=stdout)
        worker.wait.return_value = 0
        directory = self.root / "control"
        state = {"available": True, "report": {"available": True}}
        class Capture(dict):
            deadline = time.monotonic() + (1000 if bad_deadline else 15)
            def finish_recording(self):
                events.append("finish")
                if fail_finish:
                    raise TimeoutError("finish refused")
        cap = Capture(state)
        @contextmanager
        def perf(*args, **kwargs):
            self.assertEqual(args[:3], ("record", PID, 5))
            self.assertEqual(kwargs, {"event": "cpu-clock", "target": worker})
            events.append("enable-ack")
            if fail_enter:
                if startup_cleanup_failure:
                    probe.save_new(directory / "perf.json", {"available": False, "cleanup_unresolved": True, "cleanup_error": "reap refused"})
                raise PermissionError("sudo refused")
            try:
                yield cap
            finally:
                events.append("capture-finally")
        result_receipt = receipt(completed=False, process_cpu_ns=1000) if bad_receipt else receipt()
        lines = iter((b"ready\n", b"measured\n", json.dumps(result_receipt).encode() + b"\n"))
        def read(*args):
            line = next(lines)
            events.append("measured" if line == b"measured\n" else "read")
            return line
        def snapshot(pid):
            events.append("snapshot")
            return {"pid": pid, "start_ticks": 5, "user_ticks": 50, "system_ticks": 1, "ticks_per_second": 100, "executable": str(Path(sys.executable).resolve())}
        def cleanup(child):
            events.append("cleanup")
            if fail_cleanup:
                raise RuntimeError("cleanup refused")
        real_reader = probe.read_regular
        raw = {"executable_mapping_matches": True, "sample_records": 5, "total_period": 100,
               "lost": 0, "lost_samples": 0}
        with patch.object(probe, "spawn", return_value=worker), patch.object(probe, "stop", side_effect=cleanup), \
             patch.object(probe.os, "set_blocking"), patch.object(probe.os, "read", return_value=b""), \
             patch.object(probe, "read_line", side_effect=read), \
             patch.object(probe, "write_gate", side_effect=lambda fd, gate, dl: events.append(gate)), \
             patch.object(probe, "proc_snapshot", side_effect=snapshot), patch.object(probe, "perf_pass", side_effect=perf), \
             patch.object(probe, "read_regular", side_effect=lambda path, limit: real_reader(path, limit) if Path(path).name == "perf.json" else b"data"), patch.object(probe, "parse_perf", return_value=raw), \
             patch.object(probe, "report_counts", return_value={"samples": 6 if bad_header else 5, "period": 100, "lost": 0}):
            result = probe.collect_control("cpu-clock", "continuous", directory)
        return result, events, directory

    def test_fence_snapshot_and_report_order(self):
        result, events, _ = self.control()
        self.assertTrue(result["valid"], result)
        self.assertEqual(events, ["read", "enable-ack", "snapshot", b"run\n", "measured", "snapshot", "finish", b"report\n", "read", "capture-finally", "cleanup"])
        self.assertEqual(result["samples_per_process_cpu_second"], 5 / .50005)

    def test_enable_refusal_never_releases_run_and_reaps_worker(self):
        result, events, directory = self.control(fail_enter=True)
        self.assertFalse(result["valid"])
        self.assertNotIn(b"run\n", events)
        self.assertIn("cleanup", events)
        self.assertTrue((directory / "control.json").exists())

    def test_failed_enter_cleanup_metadata_recovered_and_vetoed(self):
        result, events, directory = self.control(fail_enter=True, startup_cleanup_failure=True)
        self.assertFalse(result["valid"])
        self.assertTrue(result["cleanup_unresolved"])
        self.assertEqual(result["perf"]["cleanup_error"], "reap refused")
        self.assertNotIn(b"run\n", events)
        self.assertIn("cleanup", events)

    def test_untrusted_excess_deadline_refused_before_run(self):
        result, events, _ = self.control(bad_deadline=True)
        self.assertFalse(result["valid"])
        self.assertNotIn(b"run\n", events)
        self.assertIn("cleanup", events)

    def test_finish_refusal_never_requests_report_and_reaps(self):
        result, events, _ = self.control(fail_finish=True)
        self.assertFalse(result["valid"])
        self.assertNotIn(b"report\n", events)
        self.assertIn("capture-finally", events)
        self.assertIn("cleanup", events)

    def test_cleanup_unresolved_vetoes_good_measurement(self):
        result, events, _ = self.control(fail_cleanup=True)
        self.assertFalse(result["valid"])
        self.assertTrue(result["cleanup_unresolved"])

    def test_invalid_receipt_preserved_and_capture_reaped(self):
        result, events, directory = self.control(bad_receipt=True)
        self.assertFalse(result["valid"])
        self.assertTrue((directory / "worker.json").exists())
        self.assertIn("capture-finally", events)
        self.assertIn("cleanup", events)

    def test_report_reconciliation_required(self):
        result, _, _ = self.control(bad_header=True)
        self.assertFalse(result["valid"])
        self.assertIn("mismatch", result["reason"])

    def test_serial_plan_stops_after_invalid_without_extension(self):
        calls = []
        def collect(event, pattern, directory):
            calls.append((event, pattern))
            return {"valid": False, "event": event, "pattern": pattern}
        with patch.object(probe.sys, "platform", "linux"), patch.object(probe.shutil, "which", return_value="/existing/tool"), \
             patch.object(probe, "command", return_value="source"), patch.object(probe, "digest_file", return_value={"sha256": "a" * 64}), \
             patch.object(probe, "collect_control", side_effect=collect), patch("builtins.print"):
            self.assertEqual(probe.run_probe(self.root / "new"), 1)
        self.assertEqual(calls, [probe.PLAN[0]])
        summary = json.loads((self.root / "new/summary.json").read_bytes())
        self.assertEqual(len(summary["unattempted"]), 3)

    def test_four_controls_once_in_fixed_serial_order_and_complete_index(self):
        calls = []
        def collect(event, pattern, directory):
            calls.append((event, pattern))
            return {"valid": True, "event": event, "pattern": pattern}
        with patch.object(probe.sys, "platform", "linux"), patch.object(probe.shutil, "which", return_value="/existing/tool"), \
             patch.object(probe, "command", return_value="source"), patch.object(probe, "digest_file", return_value={"sha256": "a" * 64}), \
             patch.object(probe, "collect_control", side_effect=collect), patch("builtins.print"):
            self.assertEqual(probe.run_probe(self.root / "new"), 0)
        self.assertEqual(calls, list(probe.PLAN))
        index = json.loads((self.root / "new/evidence-index.json").read_bytes())
        self.assertIn("summary.json", [f["path"] for f in index["files"]])
        self.assertEqual(len(set(calls)), 4)

    def test_whole_output_budget_reserves_metadata_and_preserves_originals(self):
        for name in ("one", "two"):
            (self.root / name).write_bytes(b"x" * 32769)
        with patch.object(probe, "OUTPUT_LIMIT", probe.TEST_LOG_LIMIT + 2 * probe.META_LIMIT), self.assertRaisesRegex(ValueError, "whole probe"):
            probe.inventory(self.root)
        self.assertEqual((self.root / "one").stat().st_size, 32769)
        self.assertEqual((self.root / "two").stat().st_size, 32769)

    def test_inventory_failure_is_retained_and_not_reported_valid(self):
        with patch.object(probe.sys, "platform", "linux"), patch.object(probe.shutil, "which", return_value=None), \
             patch.object(probe, "inventory", side_effect=ValueError("unsafe output type")), patch("builtins.print"):
            self.assertEqual(probe.run_probe(self.root / "new"), 1)
        index = json.loads((self.root / "new/evidence-index.json").read_bytes())
        self.assertFalse(index["complete"])
        self.assertEqual(index["reason"], "unsafe output type")

    def test_missing_tools_retained_explicitly_without_launch(self):
        with patch.object(probe.sys, "platform", "linux"), patch.object(probe.shutil, "which", return_value=None), \
             patch.object(probe, "collect_control") as collect, patch("builtins.print"):
            self.assertEqual(probe.run_probe(self.root / "new"), 1)
        collect.assert_not_called()
        summary = json.loads((self.root / "new/summary.json").read_bytes())
        self.assertIn("required existing tool unavailable", summary["reason"])
        self.assertEqual(len(summary["unattempted"]), 4)
        self.assertTrue((self.root / "new/evidence-index.json").exists())

    def test_fresh_output_refuses_reuse_and_preserves_existing(self):
        directory = self.root / "existing"
        directory.mkdir()
        (directory / "original").write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            probe.fresh_output(directory)
        self.assertEqual((directory / "original").read_bytes(), b"keep")

    def test_bounded_metadata_refuses_before_creating_file(self):
        with self.assertRaises(ValueError):
            probe.save_new(self.root / "large.json", {"large": "x" * 2000}, 1024)
        self.assertFalse((self.root / "large.json").exists())

    def test_linked_evidence_refused_without_touching_original(self):
        original, alias = self.root / "original", self.root / "alias"
        original.write_bytes(b"preserve")
        os.link(original, alias)
        with self.assertRaisesRegex(ValueError, "linked"):
            probe.read_regular(original, 1024)
        self.assertEqual(original.read_bytes(), b"preserve")

    def test_inventory_enforces_actual_per_file_bound(self):
        path = self.root / "perf.data"
        with path.open("wb") as stream:
            stream.truncate(probe.QUOTA + 1)
        with self.assertRaisesRegex(ValueError, "oversized"):
            probe.inventory(self.root)

    def test_report_counts_include_warning_omissions_without_losing_original(self):
        (self.root / "perf-report.txt").write_text("# Samples: 1,234 of event cpu-clock\n# Event count (approx.): 999\n# Total Lost Samples: 3\n" + "warning retained\n" * 30)
        (self.root / "perf-command.log").write_text("perf version test\n")
        result = probe.report_counts(self.root)
        self.assertEqual((result["samples"], result["period"], result["lost"]), (1234, 999, 3))
        self.assertGreater(result["warnings_omitted"], 0)
        self.assertEqual((self.root / "perf-report.txt").read_text().count("warning retained"), 30)

    @unittest.skipUnless(sys.platform == "linux", "Linux nonblocking pipe primitive; no helper launched")
    def test_pipe_eof_oversize_and_expired_deadline(self):
        for data, limit, error in ((b"partial", 16, EOFError), (b"long line\n", 4, ValueError)):
            r, w = os.pipe()
            try:
                os.set_blocking(r, False)
                os.write(w, data)
                os.close(w)
                w = None
                with self.assertRaises(error):
                    probe.read_line(r, time.monotonic() + 1, limit)
                with self.assertRaises(TimeoutError):
                    probe.read_line(r, time.monotonic() - 1, limit)
            finally:
                os.close(r)
                if w is not None:
                    os.close(w)


if __name__ == "__main__":
    unittest.main()
