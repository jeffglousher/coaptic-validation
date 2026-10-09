"""Focused contract tests for session integrity, accounting and statistical units."""
import copy
import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import campaign as bench


def case():
    return {"id": "small", "protocol": "coap", "security": "plaintext", "bytes": 64,
            "concurrency": 1, "operations": 2, "warmup": 0, "timeout_ms": 50, "mode": "con"}


def sample():
    return {"schema": "coaptic-load/1", "protocol": "coap", "security": "plaintext", "mode": "con", "concurrency": 1,
            "warmup": 0, "warmup_failed": 0, "attempted": 2, "completed": 2, "failed": 0,
            "verified_bytes": 128, "elapsed_ns": 1000, "latencies_ns": [100, 200]}


def manifest():
    return {"schema": bench.SCHEMA, "peers": [{"id": name, "protocol": "coap", "security": "plaintext", "identity": name,
            "server": [sys.executable, "{port}"], "driver": [sys.executable, "{operations}"]}
            for name in ("coaptic", "peer-b", "peer-c")], "cases": [case()]}


def evidence(root, count=6, failed_reference=False, resumed=False, overlap=False):
    plan = bench.create_plan(manifest(), count, 42)
    plan_file = Path(root) / "plan.json"
    bench.write_new(plan_file, plan)
    plan_hash = bench.digest(plan_file)
    origin = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    for number, cells in enumerate(plan["schedule"]):
        start = (origin + datetime.timedelta(minutes=number * 10)).isoformat()
        finish = (origin + datetime.timedelta(minutes=number * 10, seconds=1)).isoformat()
        if overlap and number == 1:
            start = (origin + datetime.timedelta(milliseconds=500)).isoformat()
            finish = (origin + datetime.timedelta(milliseconds=1500)).isoformat()
        entries = []
        for cell in cells:
            data = sample()
            if failed_reference and number == 0 and cell["peer"] == "coaptic":
                data.update(completed=1, failed=1, verified_bytes=64, latencies_ns=[100])
            path = Path(root) / f"window-{number}" / f"{cell['case']}--{cell['peer']}.json"
            bench.write_new(path, {"plan_sha256": plan_hash, "window": number, **cell,
                                  "started": start, "finished": finish, "sample": data})
            entries.append({"path": str(path.relative_to(root)), "sha256": bench.digest(path)})
        bench.write_new(Path(root) / f"window-{number}.json", {"plan_sha256": plan_hash,
            "window": number, "started": start, "finished": finish, "resumed": resumed and number == 0,
            "cells": entries})


class CampaignTests(unittest.TestCase):
    def test_server_startup_failure_retains_exit_and_stderr(self):
        peer = {
            "server": [sys.executable, "-c", "import sys; print('fixture bind failed', file=sys.stderr); sys.exit(17)"],
            "driver": [sys.executable, "-c", "print('{{}}')"],
        }
        with self.assertRaisesRegex(ValueError, "server_exit=17.*fixture bind failed"):
            bench.run_cell(peer, case())

    def test_request_tail_is_not_average_session_tail(self):
        with tempfile.TemporaryDirectory() as root:
            evidence(root)
            row = next(r for r in bench.analyze(root, "coaptic")["summary"] if r["peer"] == "coaptic")
            self.assertEqual(row["successful_request_latency_ns"],
                             {"count": 12, "mean": 150, "p99": 200, "min": 100, "max": 200})
            self.assertEqual(row["session_mean_latency_ns"],
                             {"count": 6, "mean": 150, "p99": 150, "min": 150, "max": 150})
            self.assertEqual(row["session_statistics"][0]["latency_ns"]["p99"], 199)

    def test_empty_latency_summary_does_not_invent_zero(self):
        self.assertEqual(bench.descriptive([]),
                         {"count": 0, "mean": None, "p99": None, "min": None, "max": None})

    def test_unequal_completion_counts_have_distinct_request_and_session_weights(self):
        with tempfile.TemporaryDirectory() as root:
            evidence(root, failed_reference=True)
            row = next(r for r in bench.analyze(root, "coaptic")["summary"] if r["peer"] == "coaptic")
            self.assertAlmostEqual(row["successful_request_latency_ns"]["mean"], 1600 / 11)
            self.assertAlmostEqual(row["session_mean_latency_ns"]["mean"], 850 / 6)
            self.assertEqual(row["failed_requests"], 1)
            self.assertFalse(row["comparison_eligible"])

    def test_aggregate_input_budget_refuses_before_reading_excess_cell(self):
        with tempfile.TemporaryDirectory() as root:
            evidence(root)
            budget = (Path(root) / "plan.json").stat().st_size + (Path(root) / "window-0.json").stat().st_size
            with patch.object(bench, "MAX_ANALYSIS_BYTES", budget), patch.object(bench, "read", wraps=bench.read) as read:
                with self.assertRaisesRegex(ValueError, "aggregate analysis input budget"):
                    bench.analyze(root, "coaptic")
                self.assertEqual(read.call_count, 2)

    def test_aggregate_latency_budget_refuses_before_pooling(self):
        with tempfile.TemporaryDirectory() as root:
            evidence(root)
            with patch.object(bench, "MAX_ANALYSIS_SAMPLES", 1), patch.object(bench, "descriptive") as summary:
                with self.assertRaisesRegex(ValueError, "aggregate analysis latency budget"):
                    bench.analyze(root, "coaptic")
                summary.assert_not_called()

    def test_accounting_and_representation_are_not_just_success_exit(self):
        for field, value in (("completed", 1), ("failed", 1), ("verified_bytes", 127),
                             ("elapsed_ns", 0), ("latencies_ns", [100]), ("protocol", "http3"),
                             ("mode", "non"), ("security", "OSCORE"), ("attempted", True), ("verified_bytes", True)):
            data = sample()
            data[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bench.validate_sample(data, case())

    def test_failures_remain_in_attempt_denominator(self):
        data = dict(sample(), completed=1, failed=1, verified_bytes=64, latencies_ns=[100])
        bench.validate_sample(data, case())

    def test_nan_and_fractional_timing_refuse(self):
        for value in (float("nan"), 1.5, True, -1):
            data = dict(sample(), latencies_ns=[value, 200])
            with self.assertRaises(ValueError):
                bench.validate_sample(data, case())

    def test_balanced_comparison_order_not_repeating_best_first(self):
        plan = bench.create_plan(manifest(), 6, 42)
        for peer in ("coaptic", "peer-b", "peer-c"):
            positions = [next(i for i, cell in enumerate(window) if cell["peer"] == peer) for window in plan["schedule"]]
            self.assertEqual(sorted(positions), [0, 0, 1, 1, 2, 2])
        again = bench.create_plan(manifest(), 6, 42)
        self.assertEqual(plan["schedule"], again["schedule"])

    def test_sparse_or_smoke_data_cannot_establish_win(self):
        self.assertIsNone(bench.paired_interval([2.0] * 4)["confidence_95"])
        plan = bench.create_plan(manifest(), 6, 4, smoke=True)
        self.assertTrue(plan["smoke"])
        self.assertEqual(plan["cases"][0]["operations"], 4)

    def test_paired_session_bootstrap_is_deterministic(self):
        interval = bench.paired_interval([1.2, 1.1, 1.3, 1.2, 1.25, 1.18])
        self.assertEqual(interval, bench.paired_interval([1.2, 1.1, 1.3, 1.2, 1.25, 1.18]))
        self.assertGreater(interval["confidence_95"][0], 1)

    def test_malformed_or_oversized_driver_event(self):
        with self.assertRaises(ValueError):
            bench.execute([sys.executable, "-c", "print('not json')"], 3)
        with patch.object(bench, "MAX_OUTPUT", 100), self.assertRaises(ValueError):
            bench.execute([sys.executable, "-c", "print('x'*200)"], 3)

    def test_json_nonobjects_and_depth_are_invalid_not_runner_crashes(self):
        for expression in ("[]", "None", "42", "'text'"):
            with self.subTest(expression=expression), self.assertRaisesRegex(ValueError, "JSON object"):
                bench.execute([sys.executable, "-c", f"import json; print(json.dumps({expression}))"], 3)
        with self.assertRaises(ValueError):
            bench.execute([sys.executable, "-c", "print('['*2000+'0'+']'*2000)"], 3)

    def test_output_cap_terminates_a_chatty_process_before_its_deadline(self):
        with patch.object(bench, "MAX_OUTPUT", 100), self.assertRaisesRegex(ValueError, "oversize"):
            bench.execute([sys.executable, "-c", "import os,time; os.write(1,b'x'*8192); time.sleep(10)"], 2)
        with patch.object(bench, "MAX_OUTPUT", 100), self.assertRaisesRegex(ValueError, "oversize"):
            bench.execute([sys.executable, "-c", "import os,time; os.write(2,b'x'*8192); time.sleep(10)"], 2)

    def test_driver_deadline_is_not_protocol_failure(self):
        with self.assertRaisesRegex(ValueError, "process deadline"):
            bench.execute([sys.executable, "-c", "import time; time.sleep(5)"], .05)

    def test_artifacts_never_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "result.json"
            bench.write_new(path, {"original": 1})
            with self.assertRaises(FileExistsError):
                bench.write_new(path, {"changed": 2})
            self.assertEqual(bench.read(path), {"original": 1})

    def test_empty_or_duplicate_matrix_refuses(self):
        for broken in (dict(manifest(), peers=[]), dict(manifest(), cases=[])):
            with self.assertRaises(ValueError):
                bench.validate_manifest(broken)
        broken = manifest()
        broken["peers"].append(copy.deepcopy(broken["peers"][0]))
        with self.assertRaises(ValueError):
            bench.validate_manifest(broken)

    def test_case_bounds_are_not_booleans(self):
        broken = manifest()
        broken["cases"][0]["operations"] = True
        with self.assertRaises(ValueError):
            bench.validate_manifest(broken)

    def test_protocol_and_security_strata_cannot_be_mislabelled(self):
        broken = manifest()
        broken["cases"][0]["mode"] = "warm"
        with self.assertRaisesRegex(ValueError, "request mode"):
            bench.create_plan(broken, 1, 42)
        broken = manifest()
        broken["cases"][0]["security"] = "OSCORE"
        with self.assertRaisesRegex(ValueError, "compatible peer"):
            bench.create_plan(broken, 1, 42)

    def test_resume_preserves_earliest_cell_and_never_reruns_it(self):
        with tempfile.TemporaryDirectory() as root:
            plan = bench.create_plan(manifest(), 1, 42)
            plan_file = Path(root) / "plan.json"
            bench.write_new(plan_file, plan)
            old = "2020-01-01T00:00:00+00:00"
            first = plan["schedule"][0][0]
            path = Path(root) / "window-0" / f"{first['case']}--{first['peer']}.json"
            bench.write_new(path, {"schema": bench.SCHEMA, "plan_sha256": bench.digest(plan_file),
                "window": 0, **first, "started": old, "finished": old, "sample": sample()})
            original = bench.digest(path)
            with patch.object(bench, "run_cell", return_value={"sample": sample(), "finished": bench.utc()}) as run, patch("builtins.print"):
                bench.run_window(root, 0)
            self.assertEqual(run.call_count, 2)
            self.assertEqual(bench.digest(path), original)
            window = bench.read(Path(root) / "window-0.json")
            self.assertEqual(window["started"], old)
            self.assertTrue(window["resumed"])
            self.assertFalse(bench.analyze(root, "coaptic")["sessions"][0]["comparison_eligible"])

    def test_incomplete_session_cannot_be_scored(self):
        with tempfile.TemporaryDirectory() as root:
            plan = bench.create_plan(manifest(), 1, 42)
            plan_file = Path(root) / "plan.json"
            bench.write_new(plan_file, plan)
            bench.write_new(Path(root) / "window-0.json", {"plan_sha256": bench.digest(plan_file), "window": 0,
                "started": bench.utc(), "finished": bench.utc(), "cells": []})
            with self.assertRaisesRegex(ValueError, "incomplete"):
                bench.analyze(root, "coaptic")

    def test_dependency_mutation_changes_identity(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "library.py"
            path.write_text("version = 1", encoding="utf8")
            peer = dict(manifest()["peers"][0], dependency_trees=[root])
            before = bench.peer_identity(peer)
            path.write_text("version = 2", encoding="utf8")
            self.assertNotEqual(before, bench.peer_identity(peer))

    def test_failed_reference_cannot_be_hidden_by_five_clean_pairs(self):
        with tempfile.TemporaryDirectory() as root:
            evidence(root, failed_reference=True)
            report = bench.analyze(root, "coaptic")
            for row in report["summary"]:
                self.assertFalse(row["comparison_eligible"])
                self.assertEqual(row["excluded_comparison_pairs"], 1)
                self.assertEqual(row["completed_rate_vs_reference"]["sessions"], 5)

    def test_resumed_blocks_remain_descriptive_not_independent(self):
        with tempfile.TemporaryDirectory() as root:
            evidence(root, resumed=True)
            report = bench.analyze(root, "coaptic")
            self.assertTrue(report["sessions"][0]["resumed"])
            self.assertTrue(all(not row["comparison_eligible"] for row in report["summary"]))
        with tempfile.TemporaryDirectory() as root:
            evidence(root)
            self.assertTrue(all(row["comparison_eligible"] for row in bench.analyze(root, "coaptic")["summary"]))

    def test_campaign_lock_refuses_a_second_process_and_releases(self):
        with tempfile.TemporaryDirectory() as root:
            code = "import sys; sys.path.insert(0,sys.argv[1]); import campaign; campaign.run_window(sys.argv[2],0)"
            with bench.campaign_lock(root):
                result = bench.subprocess.run([sys.executable, "-c", code,
                    str(Path(bench.__file__).parent), root], capture_output=True, timeout=3)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"campaign already running", result.stderr)
            with bench.campaign_lock(root):
                pass

    def test_runtime_tuning_is_immutable(self):
        data = manifest()
        data["runtime_environment"] = bench.host()["runtime_environment"]
        with patch.dict(bench.os.environ, GOMAXPROCS="123"):
            with self.assertRaisesRegex(ValueError, "tuning changed"):
                bench.create_plan(data, 1, 42)

    def test_runner_mutation_refuses_saved_plan(self):
        with tempfile.TemporaryDirectory() as root:
            plan = bench.create_plan(manifest(), 1, 42)
            plan["runner_sha256"] = "changed"
            bench.write_new(Path(root) / "plan.json", plan)
            with self.assertRaisesRegex(ValueError, "runner changed"):
                bench.run_window(root, 0)
            with self.assertRaisesRegex(ValueError, "runner changed"):
                bench.analyze(root, "coaptic")

    def test_overlap_excludes_both_affected_sessions_but_not_future_ones(self):
        with tempfile.TemporaryDirectory() as root:
            evidence(root, overlap=True)
            periods = bench.analyze(root, "coaptic")["sessions"]
            eligibility = {p["window"]: p["comparison_eligible"] for p in periods}
            self.assertFalse(eligibility[0])
            self.assertFalse(eligibility[1])
            self.assertTrue(all(eligibility[number] for number in range(2, 6)))


if __name__ == "__main__":
    unittest.main()
