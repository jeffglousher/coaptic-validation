"""Refuse incomplete or mismatched native measurements and missing costs."""
import copy
import unittest
from native_diagnostic import validate_report


class ReportTests(unittest.TestCase):
    def test_complete_report_and_hostile_accounting(self):
        valid = dict(schema="coaptic-native-complete/1", bytes=64, completed=2,
                     policy="spin", security="oscore", latencies_ns=[20, 30],
                     elapsed_ns=70, received_datagrams=2, sent_datagrams=2,
                     core_heap_limit_bytes=1000, app_inline_bytes=1000,
                     verification_heap_bytes=128, timing_heap_bytes=16, udp_scratch_bytes=1473)
        validate_report(valid, 64, 2, "spin", "oscore")
        for change in (dict(completed=1), dict(bytes=63), dict(security="unprotected"),
                       dict(policy="sleep1"), dict(latencies_ns=[20]),
                       dict(latencies_ns=[20, -1]), dict(latencies_ns=[True, 30]),
                       dict(core_heap_limit_bytes=None), dict(app_inline_bytes=False),
                       dict(received_datagrams=1), dict(sent_datagrams=1), dict(elapsed_ns=40)):
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
