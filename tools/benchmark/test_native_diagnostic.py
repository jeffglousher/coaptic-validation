"""Refuse incomplete or mismatched native measurements and missing costs."""
import copy
import io
import unittest
from native_diagnostic import control_line, cpu_cost, measure, validate_report


class ReportTests(unittest.TestCase):
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
