"""Refuse incomplete or mismatched native measurements and missing costs."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch
from native_diagnostic import (ADMISSION_DIAGNOSTIC_LIMIT, control_line, cpu_cost, main, measure,
                               PROC_MEMORY_READ_LIMIT, PROC_MEMORY_RESULT_LIMIT, _proc_memory_fields,
                               process_memory_evidence, snapshot, server_resources,
                               validate_admission_diagnostics, validate_report)
from native_profiles import dimensions, PROFILE_SIZES


class ProcessMemoryTests(unittest.TestCase):
    STATUS = b"Name:\tnative\nVmHWM:\t12 kB\nVmPeak: 34 kB\nVmStk: 8 kB\nThreads: 1\n"
    LIMITS = b"Limit Soft Limit Hard Limit Units\nMax stack size 8388608 unlimited bytes\n"

    def test_exact_fields_units_zero_and_unlimited_limits(self):
        self.assertEqual(_proc_memory_fields(self.STATUS, "status"), dict(
            available=True, vm_hwm_bytes=12288, vm_peak_bytes=34816, vm_stk_bytes=8192, threads=1))
        for soft, hard in (("0", "0"), ("1024", "2048"), ("unlimited", "unlimited"),
                           ("0", "unlimited"), (str(2**64 - 1), "unlimited")):
            row = f"Max stack size {soft} {hard} bytes\n".encode()
            result = _proc_memory_fields(row, "limits")
            self.assertEqual(result, dict(available=True,
                stack_soft_bytes=soft if soft == "unlimited" else int(soft),
                stack_hard_bytes=hard if hard == "unlimited" else int(hard)))
        zero = self.STATUS.replace(b"12 kB", b"0 kB")
        self.assertEqual(_proc_memory_fields(zero, "status")["vm_hwm_bytes"], 0)

    def test_missing_duplicates_units_numeric_and_incomplete_refuse(self):
        for field in (b"VmHWM", b"VmPeak", b"VmStk", b"Threads"):
            lines = self.STATUS.splitlines(keepends=True)
            row = next(line for line in lines if line.startswith(field + b":"))
            for raw, reason in ((self.STATUS.replace(row, b""), "missing"),
                                (self.STATUS + row, "duplicate")):
                with self.subTest(field=field, reason=reason), self.assertRaisesRegex(ValueError, reason):
                    _proc_memory_fields(raw, "status")
        bad_status = (self.STATUS[:-1], b"", self.STATUS.replace(b"12 kB", b"12 KB"),
                      self.STATUS.replace(b"12 kB", b"12 bytes"),
                      self.STATUS.replace(b"12 kB", b"12"),
                      self.STATUS.replace(b"12 kB", b"-1 kB"),
                      self.STATUS.replace(b"12 kB", b"1.0 kB"),
                      self.STATUS.replace(b"12 kB", b"+1 kB"),
                      self.STATUS.replace(b"12 kB", b"\xff kB"),
                      self.STATUS.replace(b"12 kB", str(2**54).encode() + b" kB"),
                      self.STATUS.replace(b"12 kB", b"1" * 21 + b" kB"),
                      self.STATUS.replace(b"Threads: 1", b"Threads: 0"),
                      self.STATUS.replace(b"Threads: 1", b"Threads: 1 kB"),
                      self.STATUS.replace(b"12 kB", b" " * 129 + b"12 kB"))
        bad_limits = (b"", self.LIMITS[:-1], self.LIMITS + self.LIMITS,
                      b"Max stack size 2 1 bytes\n", b"Max stack size unlimited 1 bytes\n",
                      b"Max stack size -1 unlimited bytes\n", b"Max stack size 1 2 kB\n",
                      b"Max stack size 1 2 bytes extra\n", b"Max stack size 1 bytes\n",
                      b"Max stack size Unlimited unlimited bytes\n",
                      f"Max stack size {2**64} unlimited bytes\n".encode())
        for source, records in (("status", bad_status), ("limits", bad_limits)):
            for raw in records:
                with self.subTest(source=source, raw=raw[:150]), self.assertRaises(ValueError):
                    _proc_memory_fields(raw, source)

    def test_read_bound_refuses_full_cap_even_if_selected_fields_complete(self):
        for source, base in (("status", self.STATUS), ("limits", self.LIMITS)):
            accepted = base + b"x" * (PROC_MEMORY_READ_LIMIT - len(base) - 2) + b"\n"
            self.assertTrue(_proc_memory_fields(accepted, source)["available"])
            for raw in (accepted + b"\n", accepted + b"xx\n"):
                with self.subTest(source=source), self.assertRaisesRegex(ValueError, "read_limit"):
                    _proc_memory_fields(raw, source)

    def test_capture_serial_bounded_read_errors_and_partial_availability(self):
        for status, limits in ((self.STATUS, self.LIMITS), (PermissionError(), self.LIMITS),
                               (self.STATUS, FileNotFoundError()), (b"VmHWM: 1 kB\n", self.LIMITS),
                               (self.STATUS, self.LIMITS * PROC_MEMORY_READ_LIMIT),
                               (OSError("private path must not escape"), OSError())):
            calls = []
            def open_source(path, mode, **kwargs):
                self.assertEqual(mode, "rb")
                self.assertEqual(kwargs, dict(buffering=0))
                calls.append(str(path).replace("\\", "/"))
                data = status if path.name == "status" else limits
                if isinstance(data, Exception):
                    raise data
                stream = MagicMock()
                reader = stream.__enter__.return_value
                data_reader = io.BytesIO(data)
                counts = iter((PROC_MEMORY_READ_LIMIT - 1, 1))
                def read(n):
                    self.assertEqual(n, next(counts))
                    return data_reader.read(n)
                reader.read.side_effect = read
                return stream
            with patch("native_diagnostic.sys.platform", "linux"), \
                 patch("native_diagnostic.Path.open", autospec=True, side_effect=open_source) as opened:
                result = process_memory_evidence(123)
            self.assertEqual(calls, ["/proc/123/status", "/proc/123/limits"])
            self.assertEqual(opened.call_count, 2)
            self.assertEqual(result["available"], status == self.STATUS and limits == self.LIMITS)
            for source, data in (("status", status), ("limits", limits)):
                if isinstance(data, Exception):
                    self.assertEqual(result[source], dict(available=False, reason="read_failed"))
            encoded = json.dumps(result, separators=(",", ":"), ensure_ascii=True)
            self.assertLessEqual(len(encoded) + len(',"process_memory":'), PROC_MEMORY_RESULT_LIMIT)
            self.assertNotIn("private path", encoded)

    def test_newline_ended_short_read_without_eof_is_unavailable(self):
        for extra in (b"x", OSError("read refused")):
            with patch("native_diagnostic.sys.platform", "linux"), \
                 patch("native_diagnostic.Path.open") as opened:
                opened.return_value.__enter__.return_value.read.side_effect = [
                    self.STATUS, extra, self.LIMITS, b""]
                result = process_memory_evidence(123)
            self.assertFalse(result["available"])
            self.assertEqual(result["status"], dict(available=False,
                reason="read_failed" if isinstance(extra, OSError) else "incomplete"))
            self.assertTrue(result["limits"]["available"])

    def test_snapshot_order_cpu_denominator_and_original_errors_are_preserved(self):
        process = Mock(pid=123)
        events = []
        process.cpu_times.side_effect = lambda: (events.append("cpu") or Mock(user=1.25, system=.5))
        process.memory_info.side_effect = lambda: (events.append("memory") or Mock(_asdict=lambda: dict(rss=456)))
        with patch("native_diagnostic.process_memory_evidence", side_effect=lambda pid:
                   (events.append(("proc", pid)) or dict(available=False, reason="read_failed"))):
            after = snapshot(process)
        self.assertEqual(events, ["cpu", "memory", ("proc", 123)])
        self.assertEqual(after["memory"], dict(rss=456))
        before = dict(cpu_user_seconds=1, cpu_system_seconds=.25, memory=dict(rss=1))
        self.assertEqual(cpu_cost(dict(server=before), dict(server=after), 1000)["server"][
            "ns_per_verified_operation"], 500000)
        for failing in ("cpu_times", "memory_info"):
            with self.subTest(failing=failing), patch("native_diagnostic.process_memory_evidence") as capture:
                getattr(process, failing).side_effect = PermissionError("original")
                with self.assertRaisesRegex(PermissionError, "original"):
                    snapshot(process)
                capture.assert_not_called()
                getattr(process, failing).side_effect = None

    def test_unsupported_platform_and_invalid_pid_never_open_proc(self):
        for platform_name in ("win32", "darwin"):
            process = Mock(pid=123)
            process.cpu_times.return_value = Mock(user=1, system=2)
            process.memory_info.return_value._asdict.return_value = dict(rss=3, peak_wset=4)
            with patch("native_diagnostic.sys.platform", platform_name), patch("native_diagnostic.Path.open") as opened:
                self.assertEqual(snapshot(process), dict(cpu_user_seconds=1, cpu_system_seconds=2,
                    memory=dict(rss=3, peak_wset=4), process_memory=dict(schema="coaptic-proc-memory/1",
                    available=False, reason="unsupported_platform")))
                opened.assert_not_called()
        with patch("native_diagnostic.sys.platform", "linux"), patch("native_diagnostic.Path.open") as opened:
            for pid in (None, True, 0, -1, 2**31, "123"):
                self.assertEqual(process_memory_evidence(pid)["reason"], "invalid_pid")
            opened.assert_not_called()


class ReportTests(unittest.TestCase):
    def test_profile_ledgers_match_actual_dimensions_and_disjoint_owner_categories(self):
        for profile, sizes in PROFILE_SIZES.items():
            for size in sizes:
                expected = dimensions(profile, size)
                record = self.mio_record() | expected | dict(
                    security="oscore", app_requested_heap_bytes=0 if expected["storage"] == "fixed" else 1_000_000,
                    allocator_overhead_bytes=None, initialization_stack_bytes=None, events_heap_bytes=None)
                changes = [{key: not value if type(value) is bool else value + 1 if type(value) is int else "wrong"}
                           for key, value in expected.items()]
                changes += [dict(app_requested_heap_bytes=-1), dict(security="unprotected"),
                            dict(initialization_stack_bytes=0), dict(allocator_overhead_bytes=0),
                            dict(events_heap_bytes=0)]
                changes += [dict(app_requested_heap_bytes=1 if expected["storage"] == "fixed" else 1)]
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "server.log"
                    for delta in ({}, *changes):
                        path.write_text(json.dumps(record | delta) + "\n")
                        with self.subTest(profile=profile, size=size, delta=delta):
                            if delta:
                                with self.assertRaises(ValueError):
                                    server_resources(path, "coaptic-mio", deadline=0, server=None,
                                                     resource_profile=profile, size=size, security="oscore")
                            else:
                                self.assertEqual(server_resources(path, "coaptic-mio", deadline=0, server=None,
                                                                  resource_profile=profile, size=size,
                                                                  security="oscore"), record)

    @staticmethod
    def admission_report():
        # First A-D=100; next C-D=300, E=700 crosses P=1000; last C-D=1000
        # already forces a miss and E=0. Local debt is retained in C.
        return dict(concurrency=1, scheduled_rate_ops_per_second=1_000_000,
                    attempted=3, pacing_missed_period_operations=2,
                    pacing_late_operations=3,
                    pacing_total_lateness_ns=2100, pacing_max_lateness_ns=1000,
                    admission_diagnostics=dict(schema="coaptic-admission-interval/1",
                        storage_bytes=256, option_storage_bytes=256, admissions=3,
                        first_admissions=1, first_missed=0, first_lateness_ns=100, prior_forced_missed=1,
                        idle_sleep=dict(admissions=1, positive=1, crossed_missed=1, total_ns=700, max_ns=700),
                        no_idle_sleep=dict(admissions=1, positive=0, crossed_missed=0, total_ns=0, max_ns=0)))

    def test_admission_schema_types_bounds_and_counter_partitions(self):
        report = self.admission_report()
        validate_admission_diagnostics(report, True)
        value = report["admission_diagnostics"]
        for path, changes in (((), {"admissions": 4, "first_admissions": 0, "first_missed": 1,
                                   "prior_forced_missed": 2, "first_lateness_ns": 1001,
                                   "storage_bytes": 0, "option_storage_bytes": 2049,
                                   "schema": "unknown", "extra": "x" * 2049}),
                              (("idle_sleep",), {"admissions": 2, "positive": 0, "crossed_missed": 0,
                                                "total_ns": 699, "max_ns": 701})):
            for key, number in changes.items():
                bad = copy.deepcopy(report)
                target = bad["admission_diagnostics"]
                for member in path:
                    target = target[member]
                target[key] = number
                with self.subTest(path=path, key=key), self.assertRaises(ValueError):
                    validate_admission_diagnostics(bad, True)
        for name in (None, "idle_sleep", "no_idle_sleep"):
            target = value if name is None else value[name]
            for key in target:
                if key in ("schema", "idle_sleep", "no_idle_sleep"):
                    continue
                for number in (True, -1, "1", 1.0, None, 2**(128 if key.endswith("_ns") else 64)):
                    bad = copy.deepcopy(report)
                    destination = bad["admission_diagnostics"] if name is None else bad["admission_diagnostics"][name]
                    destination[key] = number
                    with self.subTest(bucket=name, key=key, number=number), self.assertRaises(ValueError):
                        validate_admission_diagnostics(bad, True)
        for selection in (False, 1, None):
            with self.assertRaises(ValueError):
                validate_admission_diagnostics(report, selection)
        for bad in (dict(report, concurrency=2), dict(report, scheduled_rate_ops_per_second=None),
                    dict(report, pacing_missed_period_operations=1), dict(report, attempted=2),
                    dict(report, pacing_total_lateness_ns=799), dict(report, pacing_max_lateness_ns=699),
                    dict(report, admission_diagnostics=None)):
            with self.assertRaises(ValueError):
                validate_admission_diagnostics(bad, True)
        for name in value:
            bad = copy.deepcopy(report)
            del bad["admission_diagnostics"][name]
            with self.assertRaises(ValueError):
                validate_admission_diagnostics(bad, True)

    def test_admission_maximum_integer_width_fits_existing_2k_reserve(self):
        value = self.admission_report()["admission_diagnostics"]
        for key in value:
            if type(value[key]) is int:
                value[key] = 2**(128 if key.endswith("_ns") else 64) - 1
        for name in ("idle_sleep", "no_idle_sleep"):
            for key in value[name]:
                value[name][key] = 2**(128 if key.endswith("_ns") else 64) - 1
        addition = ',"admission_diagnostics":' + json.dumps(value, separators=(",", ":"))
        self.assertLessEqual(len(addition.encode("ascii")), ADMISSION_DIAGNOSTIC_LIMIT)

    def test_admission_optin_bounds_refuse_before_process_or_credentials(self):
        for changes in (dict(rate=None), dict(concurrency=2, message_type="non"),
                        dict(admission_diagnostics=1)):
            selected = dict(rate=1000, admission_diagnostics=True) | changes
            with patch("native_diagnostic.subprocess.Popen") as spawn, \
                    patch("native_diagnostic.secrets.token_bytes") as key, self.assertRaises(ValueError):
                measure("missing", "missing", 64, 2, 0, 1000, "spin", "oscore", **selected)
            spawn.assert_not_called()
            key.assert_not_called()

    def test_admission_flag_reaches_client_only_when_explicit_and_keeps_startup_gate(self):
        for selected in (False, True):
            sut, child = Mock(pid=123), Mock(pid=124)
            for process in (sut, child):
                process.poll.return_value = None
                process.wait.return_value = 0
                process.terminate.side_effect = lambda p=process: setattr(p.poll, "return_value", 0)
            reserve, probe = MagicMock(), MagicMock()
            reserve.__enter__.return_value, probe.__enter__.return_value = reserve, probe
            reserve.getsockname.return_value = ("127.0.0.1", 5683)
            probe.bind.side_effect = OSError("bound")
            with patch("native_diagnostic.subprocess.Popen", side_effect=(sut, child)) as spawn, \
                    patch("native_diagnostic.socket.socket", side_effect=(reserve, probe)), \
                    patch("native_diagnostic.secrets.token_bytes", return_value=b"fixture"), \
                    patch("native_diagnostic.control_line", return_value="ready"), \
                    patch("native_diagnostic.server_resources", side_effect=ValueError("startup refusal")), \
                    patch("native_diagnostic.snapshot") as snapshot, \
                    self.assertRaisesRegex(ValueError, "startup refusal"):
                measure("server", "client", 64, 2, 0, 1000, "spin", "unprotected",
                        rate=1000, admission_diagnostics=selected)
            command = spawn.call_args_list[1].args[0]
            self.assertEqual(command.count("--admission-diagnostics"), int(selected))
            self.assertIn("--gated", command)
            snapshot.assert_not_called()
            child.stdin.write.assert_not_called()

    @staticmethod
    def mio_record(kind="coaptic-mio"):
        return dict(schema="coaptic-native-mio-resources/1", server_kind=kind,
                    udp_scratch_bytes=0 if kind.endswith("-direct") else 2049,
                    adapter_inline_bytes=2104, app_including_adapter_bytes=16000,
                    poll_inline_bytes=8, events_inline_bytes=24, event_capacity=8,
                    worker_threads=0, pending_kernel_operations=0,
                    runtime_heap_bytes=None, runtime_stack_bytes=None, kernel_bytes=None,
                    nesting="adapter inside App; poll/events separate", limits="inline only")

    def test_mio_ledgers_require_no_worker_no_pending_operation_and_exact_scratch(self):
        for kind in ("coaptic-mio", "coaptic-mio-direct"):
            valid = self.mio_record(kind)
            changes = [dict(udp_scratch_bytes=1), dict(adapter_inline_bytes=0),
                       dict(worker_threads=1), dict(pending_kernel_operations=1),
                       dict(worker_threads=False), dict(event_capacity=16),
                       dict(runtime_heap_bytes=0), dict(kernel_bytes=0),
                       dict(app_including_adapter_bytes=1), dict(nesting="")]
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "server.log"
                for delta in ({}, *changes):
                    record = valid | delta
                    path.write_text(json.dumps(record) + "\n")
                    with self.subTest(kind=kind, delta=delta):
                        if delta:
                            with self.assertRaises(ValueError):
                                server_resources(path, kind, deadline=0, server=None)
                        else:
                            self.assertEqual(server_resources(path, kind, deadline=0, server=None), record)

    @staticmethod
    def startup_record():
        return dict(schema="coaptic-native-server-resources/2", server_kind="coaptic-async",
                    udp_scratch_bytes=2049, adapter_inline_bytes=2104,
                    app_including_adapter_bytes=16000, loop_future_borrowing_app_bytes=12000,
                    runtime_heap_bytes=None, runtime_stack_bytes=None)

    @staticmethod
    def blocking_record():
        return dict(schema="coaptic-native-blocking-resources/1", server_kind="coaptic-blocking",
                    udp_scratch_bytes=2049, staged_datagram_capacity=1, stage_cache_metadata_bytes=56,
                    adapter_inline_bytes=2120, app_including_adapter_bytes=16072,
                    read_timeout_max_us=5000, send_timeout_us=1000, timeouts_soft=True,
                    runtime_heap_bytes=None, runtime_stack_bytes=None)

    @classmethod
    def staged_ready_record(cls):
        return dict(cls.startup_record(), server_kind="coaptic-staged-ready",
                    staged_datagram_capacity=1, stage_metadata_bytes=32,
                    driver_inline_bytes=32, send_policy="immediate_try_send_to")

    @classmethod
    def staged_mio_record(cls):
        record = dict(cls.staged_ready_record(), server_kind="coaptic-staged-mio",
                      send_policy="immediate_send_to",
                      nesting="scratch and Stage inside adapter inside App; separate Driver",
                      limits="inline only; runtime allocations and whole RAM unknown")
        del record["loop_future_borrowing_app_bytes"]
        return record

    def test_staged_mio_requires_synchronous_ownership_and_immediate_send(self):
        valid = self.staged_mio_record()
        changes = [dict(schema="coaptic-native-server-resources/1"), dict(server_kind="coaptic-mio"),
                   dict(udp_scratch_bytes=2048), dict(staged_datagram_capacity=2),
                   dict(stage_metadata_bytes=65), dict(adapter_inline_bytes=2080),
                   dict(app_including_adapter_bytes=2103), dict(runtime_heap_bytes=0),
                   dict(runtime_stack_bytes=0), dict(send_policy="immediate_try_send_to"),
                   dict(loop_future_borrowing_app_bytes=1), dict(loop_future_including_app_bytes=1),
                   dict(stage_cache_metadata_bytes=32), dict(read_timeout_max_us=5000),
                   dict(send_timeout_us=1000), dict(timeouts_soft=False)]
        for key in ("udp_scratch_bytes", "staged_datagram_capacity", "stage_metadata_bytes",
                    "adapter_inline_bytes", "app_including_adapter_bytes", "driver_inline_bytes"):
            changes.extend({key: value} for value in (True, 0, -1, 2**64, "32", 1.5))
        for key in ("nesting", "limits"):
            changes.extend({key: value} for value in ("", "x" * 1025, None, True))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            def read(record):
                path.write_bytes(json.dumps(record).encode() + b"\n")
                return server_resources(path, "coaptic-staged-mio", deadline=0, server=None)
            self.assertEqual(read(valid), valid)
            for change in changes:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    read(dict(valid, **change))
            for key in valid:
                missing = dict(valid)
                del missing[key]
                with self.subTest(missing=key), self.assertRaises(ValueError):
                    read(missing)
            for raw in (b"[]\n", b"not-json\n", b"x" * 4096 + b"\n"):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    server_resources(path, "coaptic-staged-mio", deadline=0, server=None)

    def test_staged_ready_ledger_preserves_ownership_bounds_and_immediate_send_policy(self):
        valid = self.staged_ready_record()
        changes = (dict(schema="coaptic-native-server-resources/1"),
                   dict(server_kind="coaptic-ready"), dict(udp_scratch_bytes=2048),
                   dict(staged_datagram_capacity=0), dict(staged_datagram_capacity=2),
                   dict(staged_datagram_capacity=True), dict(stage_metadata_bytes=0),
                   dict(stage_metadata_bytes=65), dict(stage_metadata_bytes=True),
                   dict(driver_inline_bytes=0), dict(driver_inline_bytes=True),
                   dict(driver_inline_bytes=2**64), dict(adapter_inline_bytes=2080),
                   dict(app_including_adapter_bytes=2103), dict(adapter_inline_bytes=True),
                   dict(loop_future_borrowing_app_bytes=0), dict(loop_future_borrowing_app_bytes=True),
                   dict(loop_future_including_app_bytes=32000), dict(runtime_heap_bytes=0),
                   dict(runtime_stack_bytes=0), dict(send_policy="blocking"),
                   dict(stage_cache_metadata_bytes=32), dict(read_timeout_max_us=5000),
                   dict(send_timeout_us=1000), dict(timeouts_soft=False))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"

            def read(record):
                path.write_bytes(json.dumps(record).encode() + b"\n")
                return server_resources(path, "coaptic-staged-ready", deadline=0, server=None)

            for future_bytes in (1, 16000, 32000):
                record = dict(valid, loop_future_borrowing_app_bytes=future_bytes)
                with self.subTest(future_bytes=future_bytes):
                    self.assertEqual(read(record), record)
            for change in changes:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    read(dict(valid, **change))
            for key in valid:
                missing = dict(valid)
                del missing[key]
                with self.subTest(missing=key), self.assertRaises(ValueError):
                    read(missing)
            for raw in (b"[]\n", b"not-json\n", b"x" * 4096 + b"\n"):
                path.write_bytes(raw)
                with self.subTest(raw=raw[:10]), self.assertRaises(ValueError):
                    server_resources(path, "coaptic-staged-ready", deadline=0, server=None)

    def test_blocking_startup_requires_bounded_metadata_and_declared_send_policy(self):
        valid = self.blocking_record()
        changes = (dict(schema="coaptic-native-server-resources/2"),
                   dict(server_kind="coaptic-async"), dict(udp_scratch_bytes=2048),
                   dict(staged_datagram_capacity=0), dict(staged_datagram_capacity=2),
                   dict(staged_datagram_capacity=True),
                   dict(stage_cache_metadata_bytes=65), dict(stage_cache_metadata_bytes=True),
                   dict(stage_cache_metadata_bytes=0), dict(adapter_inline_bytes=2104),
                   dict(app_including_adapter_bytes=2119), dict(read_timeout_max_us=5001),
                   dict(send_timeout_us=0), dict(send_timeout_us=1001), dict(timeouts_soft=False),
                   dict(timeouts_soft=1), dict(runtime_heap_bytes=0), dict(runtime_stack_bytes=0),
                   dict(loop_future_borrowing_app_bytes=1), dict(loop_future_including_app_bytes=1))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            path.write_bytes(json.dumps(valid).encode() + b"\n")
            self.assertEqual(server_resources(path, "coaptic-blocking", deadline=0, server=None), valid)
            for change in changes:
                path.write_bytes(json.dumps(dict(valid, **change)).encode() + b"\n")
                with self.subTest(change=change), self.assertRaises(ValueError):
                    server_resources(path, "coaptic-blocking", deadline=0, server=None)
            for key in valid:
                missing = dict(valid)
                del missing[key]
                path.write_bytes(json.dumps(missing).encode() + b"\n")
                with self.subTest(missing=key), self.assertRaises(ValueError):
                    server_resources(path, "coaptic-blocking", deadline=0, server=None)

    def test_async_startup_ledger_keeps_separate_borrower_and_unknown_runtime(self):
        valid = self.startup_record()
        self.assertIsNone(server_resources("unused", "coaptic-ready", deadline=0, server=None))
        with tempfile.TemporaryDirectory() as directory, patch("native_diagnostic.time.sleep") as sleep:
            path = Path(directory) / "server.log"

            def read(record):
                path.write_bytes(json.dumps(record).encode() + b"\n")
                return server_resources(path, "coaptic-async", deadline=0, server=None)

            self.assertEqual(read(valid), valid)
            # A borrowing future can be smaller or larger than its separate App.
            for child_bytes in (1, 15999, 16000, 32000):
                record = dict(valid, loop_future_borrowing_app_bytes=child_bytes)
                with self.subTest(child_bytes=child_bytes):
                    self.assertEqual(read(record), record)
            for change in (dict(server_kind="coaptic-ready"), dict(udp_scratch_bytes=2048),
                           dict(adapter_inline_bytes=2048), dict(app_including_adapter_bytes=2000),
                           dict(loop_future_borrowing_app_bytes=0),
                           dict(loop_future_borrowing_app_bytes=-1),
                           dict(loop_future_borrowing_app_bytes=True),
                           dict(loop_future_borrowing_app_bytes=None),
                           dict(loop_future_borrowing_app_bytes=2**64), dict(adapter_inline_bytes=True),
                           dict(runtime_heap_bytes=0), dict(runtime_stack_bytes=0)):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    read(dict(valid, **change))
            for key in ("runtime_heap_bytes", "runtime_stack_bytes", "loop_future_borrowing_app_bytes"):
                missing = dict(valid)
                del missing[key]
                with self.assertRaises(ValueError):
                    read(missing)
            for data in (b"[]\n", b"{}\n", b"not-json\n", b"x" * 4096 + b"\n", b"x" * 4097):
                path.write_bytes(data)
                with self.subTest(data=data[:10]), self.assertRaises(ValueError):
                    server_resources(path, "coaptic-async", deadline=0, server=None)
            sleep.assert_not_called()

    def test_startup_rejects_owned_app_schema_and_obsolete_future_field(self):
        valid = self.startup_record()
        old_field = dict(valid)
        old_field["loop_future_including_app_bytes"] = old_field.pop("loop_future_borrowing_app_bytes")
        legacy = dict(old_field, schema="coaptic-native-server-resources/1")
        records = (
            (legacy, "requires borrowing schema coaptic-native-server-resources/2"),
            (dict(valid, schema="coaptic-native-server-resources/1"), "requires borrowing schema"),
            (old_field, "obsolete owned-App loop future field"),
            (dict(valid, loop_future_including_app_bytes=32000), "obsolete owned-App loop future field"),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            for record, message in records:
                path.write_bytes(json.dumps(record).encode() + b"\n")
                with self.subTest(record=record), self.assertRaisesRegex(ValueError, message):
                    server_resources(path, "coaptic-async", deadline=0, server=None)

    def test_startup_wait_accepts_delayed_partial_line_only_after_newline(self):
        valid = self.startup_record()
        line = json.dumps(valid).encode() + b"\n"
        clock = [0.0]
        pieces = iter((line[:20], line[20:-1], b"\n"))
        server = Mock()
        server.poll.return_value = None
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            with path.open("wb", buffering=0) as writer:
                def advance(seconds):
                    clock[0] += seconds
                    writer.write(next(pieces))

                with patch("native_diagnostic.time.monotonic", side_effect=lambda: clock[0]), \
                     patch("native_diagnostic.time.sleep", side_effect=advance) as sleep:
                    self.assertEqual(server_resources(path, "coaptic-async", deadline=1, server=server), valid)
                self.assertEqual(sleep.call_count, 3)
                self.assertEqual(path.read_bytes(), line)

    def test_startup_reader_never_changes_inherited_writer_offset(self):
        valid = self.startup_record()
        line = json.dumps(valid).encode() + b"\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            with path.open("wb", buffering=0) as writer:
                writer.write(line)
                # A canary cursor catches any shared-description seek/read,
                # independent of the timing of an actual concurrent write.
                writer.seek(7)
                self.assertEqual(server_resources(path, "coaptic-async", deadline=0, server=None), valid)
                self.assertEqual(writer.tell(), 7)
                writer.seek(0, 2)
                writer.write(b"later diagnostics\n")
            self.assertEqual(path.read_bytes(), line + b"later diagnostics\n")

    def test_startup_timeout_exit_and_deadline_bounds_preserve_partial_log(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            # Even valid JSON is incomplete until its newline arrives.
            partial = json.dumps(self.startup_record()).encode()
            path.write_bytes(partial)
            server = Mock()
            server.poll.return_value = None
            with patch("native_diagnostic.time.monotonic", side_effect=(0.0, .02)), \
                 patch("native_diagnostic.time.sleep") as sleep:
                with self.assertRaisesRegex(TimeoutError, "startup ledger deadline"):
                    server_resources(path, "coaptic-async", deadline=.02, server=server)
                sleep.assert_called_once_with(.01)
            self.assertEqual(path.read_bytes(), partial)
            server.poll.return_value = 3
            with patch("native_diagnostic.time.sleep") as sleep:
                with self.assertRaisesRegex(RuntimeError, "server exited"):
                    server_resources(path, "coaptic-async", deadline=100, server=server)
                sleep.assert_not_called()
            for deadline in (float("inf"), float("nan"), True):
                with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                    server_resources(path, "coaptic-async", deadline=deadline, server=server)

    def test_zero_warmup_ready_cannot_open_snapshot_or_run_gate_before_ledger(self):
        class SnapshotBoundary(Exception):
            pass

        records = {"coaptic-async": self.startup_record(), "coaptic-blocking": self.blocking_record(),
                   "coaptic-staged-ready": self.staged_ready_record(),
                   "coaptic-staged-mio": self.staged_mio_record(),
                   "coaptic-mio": self.mio_record(),
                   "coaptic-mio-direct": self.mio_record("coaptic-mio-direct")}
        for kind, complete in ((kind, complete) for kind in records
                               for complete in (True, False)):
            record = records[kind]
            line = json.dumps(record).encode() + b"\n"
            with self.subTest(kind=kind, complete=complete):
                clock, output = [0.0], {}
                sut, client = Mock(pid=123), Mock(pid=124)
                for process in (sut, client):
                    process.poll.return_value = None
                    process.wait.return_value = 0
                    process.terminate.side_effect = lambda p=process: setattr(p.poll, "return_value", 0)
                client.stdin, client.stderr = io.StringIO(), io.StringIO()
                reserve, probe = MagicMock(), MagicMock()
                reserve.__enter__.return_value = reserve
                reserve.getsockname.return_value = ("127.0.0.1", 5683)
                probe.__enter__.return_value = probe
                probe.bind.side_effect = OSError("server is bound")

                def launch(command, **kwargs):
                    if "stdout" not in output:
                        output["stdout"] = kwargs["stdout"]
                        output["stdout"].write(line[:20])
                        output["stdout"].flush()
                        return sut
                    self.assertEqual(command[4], "0")  # Requested warmup stays zero.
                    return client

                def advance(seconds):
                    snapshots.assert_not_called()
                    self.assertEqual(client.stdin.getvalue(), "")
                    clock[0] = clock[0] + seconds if complete else 1.0
                    if complete:
                        output["stdout"].write(line[20:])
                        output["stdout"].flush()

                def snapshot_boundary(_):
                    self.assertEqual(Path(output["stdout"].name).read_bytes(), line)
                    self.assertEqual(client.stdin.getvalue(), "")
                    raise SnapshotBoundary()

                with patch("native_diagnostic.socket.socket", side_effect=(reserve, probe)), \
                     patch("native_diagnostic.subprocess.Popen", side_effect=launch), \
                     patch("native_diagnostic.control_line", return_value="ready"), \
                     patch("native_diagnostic.time.monotonic", side_effect=lambda: clock[0]), \
                     patch("native_diagnostic.time.sleep", side_effect=advance), \
                     patch("native_diagnostic.psutil.Process"), \
                     patch("native_diagnostic.snapshot", side_effect=snapshot_boundary) as snapshots:
                    with self.assertRaises(SnapshotBoundary if complete else TimeoutError) as failure:
                        measure("server", "client", 64, 1, 0, 1000, "spin", "unprotected",
                                server_kind=kind, phase_timeout_seconds=1)
                expected = line if complete else line[:20]
                self.assertEqual(failure.exception.diagnostic["server_log"], expected.decode())
                self.assertEqual(client.stdin.getvalue(), "")
                reserve.sendto.assert_not_called()
                probe.sendto.assert_not_called()

    def test_async_kind_passes_bounds_before_any_credentials_or_socket(self):
        for kind in ("coaptic-async", "coaptic-staged-ready", "coaptic-staged-mio"):
            with self.subTest(kind=kind), patch("native_diagnostic.tempfile.TemporaryDirectory",
                                              side_effect=RuntimeError("launch boundary")) as launch:
                with self.assertRaisesRegex(RuntimeError, "launch boundary"):
                    measure("missing", "missing", 64, 2, 0, 1000, "spin", "oscore", server_kind=kind)
                launch.assert_called_once()
        with patch("native_diagnostic.tempfile.TemporaryDirectory") as launch:
            with self.assertRaisesRegex(ValueError, "bounds"):
                measure("missing", "missing", 64, 2, 0, 1000, "spin", "oscore",
                        server_kind="unknown")
            launch.assert_not_called()

    def test_cli_preserves_default_and_explicit_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            for kind in (None, "coaptic-async", "coaptic-blocking", "coaptic-staged-ready", "coaptic-staged-mio"):
                output = Path(directory) / ((kind or "default") + ".json")
                argv = ["native_diagnostic.py", "--server", "server", "--client", "client",
                        "--output", str(output), "--policy", "spin", "--security", "oscore"]
                if kind is not None:
                    argv += ["--server-kind", kind]
                with patch("sys.argv", argv), patch("native_diagnostic.measure", return_value={}) as run:
                    main()
                self.assertEqual(run.call_args.kwargs["server_kind"], kind or "coaptic-reusable")
                self.assertFalse(run.call_args.kwargs["admission_diagnostics"])
                self.assertEqual(json.loads(output.read_text()), dict(passed=True))
            argv += ["--admission-diagnostics", "--rate", "1000"]
            argv[argv.index("--output") + 1] = str(Path(directory) / "admission.json")
            with patch("sys.argv", argv), patch("native_diagnostic.measure", return_value={}) as run:
                main()
            self.assertTrue(run.call_args.kwargs["admission_diagnostics"])

    def test_control_lines_refuse_unbounded_or_incomplete_reports(self):
        self.assertEqual(control_line(io.StringIO("ready\n"), 1), "ready")
        for text in ("ready", "", "x" * 129 + "\n"):
            with self.assertRaises(RuntimeError):
                control_line(io.StringIO(text), 1)

    def test_cpu_cost_uses_verified_completions_and_retains_user_and_kernel(self):
        before = {"server": dict(cpu_user_seconds=1, cpu_system_seconds=2)}
        after = {"server": dict(cpu_user_seconds=1.25, cpu_system_seconds=2.125)}
        cost = cpu_cost(before, after, 1000)["server"]
        self.assertEqual(cost["user_seconds"], .25)
        self.assertEqual(cost["system_seconds"], .125)
        self.assertEqual(cost["ns_per_verified_operation"], 375000)
        for completed in (0, -1, True):
            with self.assertRaises(ValueError):
                cpu_cost(before, after, completed)
        with self.assertRaises(ValueError):
            cpu_cost(after, before, 1000)

    def test_complete_report_and_hostile_accounting(self):
        valid = dict(schema="coaptic-native-complete/1", bytes=64, completed=2,
                     concurrency=1, message_type="con", peak_pending=1, cancelled_inflight=0,
                     pending_call_metadata_bytes=256, rx_body_slots=1, warmup=0,
                     total_sent_datagrams=2,
                     requested_operations=2, attempted=2, failed=0, unattempted=0, failure=None,
                     pacing_dropped_operations=0, scheduled_rate_ops_per_second=None,
                     achieved_ops_per_second=2e9 / 70, scheduled_dispatch_span_ns=None,
                     pacing_late_operations=0, pacing_missed_period_operations=0,
                     pacing_total_lateness_ns=0, pacing_max_lateness_ns=0,
                     policy="spin", security="oscore", latencies_ns=[20, 30],
                     elapsed_ns=70, received_datagrams=2, sent_datagrams=2,
                     core_heap_limit_bytes=1000, app_inline_bytes=1000,
                     verification_heap_bytes=128, timing_heap_bytes=16, udp_scratch_bytes=1473)
        validate_report(valid, 64, 2, "spin", "oscore")
        with self.assertRaisesRegex(ValueError, "unrequested"):
            validate_report(dict(valid, admission_diagnostics={}), 64, 2, "spin", "oscore")
        with self.assertRaisesRegex(ValueError, "paced"):
            validate_report(valid, 64, 2, "spin", "oscore", admission_diagnostics=True)
        for change in (dict(completed=1), dict(bytes=63), dict(security="unprotected"),
                       dict(policy="sleep1"), dict(latencies_ns=[20]),
                       dict(latencies_ns=[20, -1]), dict(latencies_ns=[True, 30]),
                       dict(latencies_ns=[20, 2**64]),
                       dict(core_heap_limit_bytes=None), dict(app_inline_bytes=False),
                       dict(received_datagrams=1), dict(sent_datagrams=1), dict(elapsed_ns=40),
                       dict(failed=1), dict(attempted=3), dict(unattempted=1),
                       dict(pacing_dropped_operations=1), dict(failure="timeout"),
                       dict(scheduled_rate_ops_per_second=2000), dict(achieved_ops_per_second=1),
                       dict(pacing_late_operations=3), dict(pacing_missed_period_operations=1)):
            bad = copy.deepcopy(valid)
            bad.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_report(bad, 64, 2, "spin", "oscore")
        validate_report(valid, 64, 2, "spin", "oscore")
        with self.assertRaises(ValueError):
            validate_report([], 64, 2, "spin", "oscore")
        blockwise = dict(valid, bytes=2048)
        with self.assertRaises(ValueError):
            validate_report(blockwise, 2048, 2, "spin", "oscore")

        concurrent = dict(valid, concurrency=2, message_type="non", rx_body_slots=2,
                          peak_pending=2, latencies_ns=[50, 60])
        validate_report(concurrent, 64, 2, "spin", "oscore", concurrency=2, message_type="non")
        for change in (dict(concurrency=True), dict(concurrency=1), dict(message_type="con"),
                       dict(peak_pending=3), dict(cancelled_inflight=1), dict(rx_body_slots=1),
                       dict(total_sent_datagrams=60001), dict(warmup=1),
                       dict(latencies_ns=[70, 71])):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_report(dict(concurrent, **change), 64, 2, "spin", "oscore",
                                concurrency=2, message_type="non")
        for field in ("concurrency", "message_type"):
            old = dict(valid)
            del old[field]
            with self.assertRaises(ValueError):
                validate_report(old, 64, 2, "spin", "oscore")
        impossible = dict(concurrent, completed=3, requested_operations=3, attempted=3,
                          latencies_ns=[60, 60, 60], received_datagrams=3, sent_datagrams=3,
                          total_sent_datagrams=3, achieved_ops_per_second=3e9 / 70)
        with self.assertRaises(ValueError):
            validate_report(impossible, 64, 3, "spin", "oscore", concurrency=2, message_type="non")

    def test_concurrent_con_refused_before_process_or_credentials(self):
        for concurrency, message_type in ((2, "con"), (0, "non"), (5, "non"), (True, "non")):
            with self.subTest(concurrency=concurrency), self.assertRaisesRegex(ValueError, "bounds"):
                measure("missing", "missing", 64, 2, 0, 1000, "spin", "oscore",
                        concurrency=concurrency, message_type=message_type)


if __name__ == "__main__":
    unittest.main()
