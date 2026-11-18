import copy
import unittest

from recovery_grading import grade_reconnect


class CorrelationTests(unittest.TestCase):
    def fixture(self):
        run = "a" * 32
        line = (f"COAPTIC_WIFI_RECOVERY run_id={run} connected=true disabled_at_us=30000000 "
                "enabled_at_us=31000000 reconnect_us=4000000 first_rx_us=29505000 "
                "first_rx_token=0000000000000001 after_rx_us=0 sample_rx_us=0")
        rows = [
            {"case": "reconnect_call", "index": 0, "token": "0000000000000001", "start_ns": 24_500_000_000,
             "elapsed_ns": 10_000_000, "identity_verified": True},
            {"case": "reconnect_call", "index": 1, "token": "0000000000000002", "start_ns": 25_100_000_000,
             "elapsed_ns": 6_000_000_000, "identity_verified": True},
            {"case": "reconnect_call", "index": 2, "token": "0000000000000003", "start_ns": 31_400_000_000,
             "elapsed_ns": 10_000_000, "identity_verified": True},
            {"passed": True, "run_id": run},
        ]
        return line, rows, run

    def test_calibrated_outage_overlap_requires_following_fresh_call(self):
        line, rows, run = self.fixture()
        self.assertEqual(grade_reconnect(line, rows, run)["delayed_call"], 1)
        for change in ("unrelated", "no-fresh", "slow-calibration", "wrong-source", "no-connection", "late-duplicate", "ends-before-reconnect"):
            with self.subTest(change=change):
                changed = copy.deepcopy(rows)
                changed_line = line
                if change == "unrelated": changed[1]["start_ns"] = 16_000_000_000
                elif change == "no-fresh": changed[2]["elapsed_ns"] = 1_000_000_000
                elif change == "slow-calibration": changed[0]["elapsed_ns"] = 200_000_000
                elif change == "wrong-source": changed_line = line.replace(run, "b" * 32)
                elif change == "no-connection": changed_line = line.replace("connected=true", "connected=false")
                elif change == "ends-before-reconnect": changed[1]["elapsed_ns"] = 1_000_000_000
                elif change == "late-duplicate":
                    changed_line = line.replace("first_rx_token=0000000000000001", "first_rx_token=0000000000000099")
                    changed_line += " sample_rx_token=0000000000000001 sample_rx_us=29505000"
                with self.assertRaises(AssertionError):
                    grade_reconnect(changed_line, changed, run)


if __name__ == "__main__":
    unittest.main()
