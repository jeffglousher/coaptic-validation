"""Refuse incomplete or mismatched native measurements and missing costs."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch
from native_diagnostic import control_line, cpu_cost, main, measure, server_resources, validate_report


class ReportTests(unittest.TestCase):
    @staticmethod
    def startup_record():
        return dict(schema="coaptic-native-server-resources/1", server_kind="coaptic-async",
                    udp_scratch_bytes=2049, adapter_inline_bytes=2104,
                    app_including_adapter_bytes=16000, loop_future_including_app_bytes=32000,
                    runtime_heap_bytes=None, runtime_stack_bytes=None)

    def test_async_startup_ledger_keeps_nested_sizes_and_unknown_runtime(self):
        valid = self.startup_record()
        self.assertIsNone(server_resources("unused", "coaptic-ready", deadline=0, server=None))
        with tempfile.TemporaryDirectory() as directory, patch("native_diagnostic.time.sleep") as sleep:
            path = Path(directory) / "server.log"

            def read(record):
                path.write_bytes(json.dumps(record).encode() + b"\n")
                return server_resources(path, "coaptic-async", deadline=0, server=None)

            self.assertEqual(read(valid), valid)
            for change in (dict(server_kind="coaptic-ready"), dict(udp_scratch_bytes=2048),
                           dict(adapter_inline_bytes=2048), dict(app_including_adapter_bytes=2000),
                           dict(loop_future_including_app_bytes=15999), dict(adapter_inline_bytes=True),
                           dict(runtime_heap_bytes=0), dict(runtime_stack_bytes=0)):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    read(dict(valid, **change))
            for key in ("runtime_heap_bytes", "runtime_stack_bytes"):
                missing = dict(valid)
                del missing[key]
                with self.assertRaises(ValueError):
                    read(missing)
            for data in (b"[]\n", b"{}\n", b"not-json\n", b"x" * 4096 + b"\n", b"x" * 4097):
                path.write_bytes(data)
                with self.subTest(data=data[:10]), self.assertRaises(ValueError):
                    server_resources(path, "coaptic-async", deadline=0, server=None)
            sleep.assert_not_called()

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

        line = json.dumps(self.startup_record()).encode() + b"\n"
        for complete in (True, False):
            with self.subTest(complete=complete):
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
                                server_kind="coaptic-async", phase_timeout_seconds=1)
                expected = line if complete else line[:20]
                self.assertEqual(failure.exception.diagnostic["server_log"], expected.decode())
                self.assertEqual(client.stdin.getvalue(), "")
                reserve.sendto.assert_not_called()
                probe.sendto.assert_not_called()

    def test_async_kind_passes_bounds_before_any_credentials_or_socket(self):
        with patch("native_diagnostic.tempfile.TemporaryDirectory",
                   side_effect=RuntimeError("launch boundary")) as launch:
            with self.assertRaisesRegex(RuntimeError, "launch boundary"):
                measure("missing", "missing", 64, 2, 0, 1000, "spin", "oscore",
                        server_kind="coaptic-async")
            launch.assert_called_once()
        with patch("native_diagnostic.tempfile.TemporaryDirectory") as launch:
            with self.assertRaisesRegex(ValueError, "bounds"):
                measure("missing", "missing", 64, 2, 0, 1000, "spin", "oscore",
                        server_kind="unknown")
            launch.assert_not_called()

    def test_cli_preserves_default_and_explicit_async_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            for kind in (None, "coaptic-async"):
                output = Path(directory) / ("default.json" if kind is None else "async.json")
                argv = ["native_diagnostic.py", "--server", "server", "--client", "client",
                        "--output", str(output), "--policy", "spin", "--security", "oscore"]
                if kind is not None:
                    argv += ["--server-kind", kind]
                with patch("sys.argv", argv), patch("native_diagnostic.measure", return_value={}) as run:
                    main()
                self.assertEqual(run.call_args.kwargs["server_kind"], kind or "coaptic-reusable")
                self.assertEqual(json.loads(output.read_text()), dict(passed=True))

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
