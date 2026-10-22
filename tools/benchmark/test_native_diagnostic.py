"""Refuse incomplete or mismatched native measurements and missing costs."""
import copy
import io
import unittest
from native_diagnostic import control_line, cpu_cost, validate_report


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


if __name__ == "__main__":
    unittest.main()
