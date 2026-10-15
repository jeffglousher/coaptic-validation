import copy
import unittest

from hop_analysis import analyze


def fixture():
    client = []
    server = []
    mid = 0
    for iteration in range(8):
        for path, size in (("identity", 32), ("test", 7), ("large", 2000)):
            start = len(client) * 1_000_000
            events = []
            for hop in range(2 if path == "large" else 1):
                mid += 1
                host_start = start + hop * 30000
                remote_start = 500_000_000 + start + hop * 30000
                events.extend([[2, host_start + 1000, 1000, 50, mid],
                               [1, host_start + 20000, 1000, 80, mid]])
                server.extend([[1, remote_start, 1000, 50, mid],
                               [3, remote_start + 3000, 1000, 100, 65536],
                               [4, remote_start + 5000, 2000, 100, 65536],
                               [3, remote_start + 8000, 1000, 100, 65536],
                               [2, remote_start + 11000, 1000, 80, mid]])
            client.append(dict(case="complete_operation", passed=True, path=path, bytes=size,
                               iteration=iteration, start_ns=start, elapsed_ns=100000,
                               prepare_ns=1000, poll_ns=8000, checkpoint_ns=500,
                               take_ns=500, verify_ns=100, sleep_ns=2000, events=events))
    client.append(dict(case="timing_campaign", passed=True, completed=24, run_id="a" * 32))
    return client, dict(passed=True, overflow=False, events=server)


class HopAnalysisTests(unittest.TestCase):
    def test_complete_trace_and_independent_epoch_shift_preserve_durations(self):
        client, server = fixture()
        baseline = analyze(client, server)
        server["run_id"] = "a" * 32
        self.assertEqual(analyze(client, server)["summary"], baseline["summary"])
        self.assertEqual(baseline["request_response_exchanges"], 32)
        self.assertEqual(baseline["datagrams"], 64)
        self.assertEqual(baseline["complete_operations"], 24)
        for row in server["events"]:
            row[1] += 43_200_000_000_000  # An unrelated 12-hour server epoch.
        self.assertEqual(analyze(client, server)["summary"], baseline["summary"])

    def test_missing_extra_wrong_size_and_ambiguous_hops_are_refused_then_recover(self):
        original_client, original_server = fixture()
        for mutation in (
            lambda c, s: s["events"].pop(),
            lambda c, s: s["events"].append(copy.deepcopy(s["events"][0])),
            lambda c, s: s["events"][0].__setitem__(3, 51),
            lambda c, s: c[0]["events"][0].__setitem__(4, True),
            lambda c, s: c[0].__setitem__("bytes", 31),
            lambda c, s: c[-1].__setitem__("passed", False),
            lambda c, s: c[0].__setitem__("poll_ns", 200000),
            lambda c, s: s.__setitem__("overflow", True),
            lambda c, s: s["events"][2].__setitem__(0, 3),
            lambda c, s: c[0].__setitem__("bytes", 32.0),
            lambda c, s: c[-1].__setitem__("completed", 24.0),
            lambda c, s: c[3].__setitem__("iteration", 0),
            lambda c, s: s.__setitem__("run_id", "b" * 32),
        ):
            with self.subTest(mutation=mutation):
                c, s = copy.deepcopy(original_client), copy.deepcopy(original_server)
                mutation(c, s)
                with self.assertRaises(ValueError):
                    analyze(c, s)
                self.assertTrue(analyze(original_client, original_server)["passed"])

    def test_device_index_gaps_and_overflow_refuse_complete_host_success(self):
        client, server = fixture()
        rows = [dict(index=i, run_id="a" * 32, kind=r[0], at_us=r[1] // 1000,
                     duration_us=r[2] // 1000, bytes=r[3], mid=r[4], result=1)
                for i, r in enumerate(server["events"])]
        device = dict(end=dict(run_id="a" * 32, overflow=False, events=len(rows)), events=rows)
        self.assertTrue(analyze(client, device)["passed"])
        for mutation in (lambda d: d["events"][0].__setitem__("index", 1),
                         lambda d: d["end"].__setitem__("overflow", True),
                         lambda d: d["events"][0].__setitem__("run_id", "b" * 32),
                         lambda d: d["events"][0].__setitem__("result", -1),
                         lambda d: d["events"][0].__setitem__("result", True),
                         lambda d: d["events"][0].__setitem__("index", False),
                         lambda d: [d["end"].__setitem__("run_id", "b" * 32), [r.__setitem__("run_id", "b" * 32) for r in d["events"]]]):
            d = copy.deepcopy(device)
            mutation(d)
            with self.assertRaises(ValueError):
                analyze(client, d)


if __name__ == "__main__":
    unittest.main()
