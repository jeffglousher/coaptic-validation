import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import comparison_report as report


def fixture():
    case = dict(bytes=64, concurrency=1, operations=2, warmup=0,
                mode="con", protocol="coap", security="unprotected")
    method = {"rounds": 3, "peers": [{"id": "Coaptic-Mio", "server": ["server", "coaptic-mio"]}], "cases": [case]}
    sample = dict(schema="coaptic-load/1", attempted=2, completed=2, failed=0,
                  elapsed_ns=100, latencies_ns=[10, 20], verified_bytes=128,
                  concurrency=1, warmup=0, warmup_failed=0,
                  mode="con", protocol="coap", security="unprotected")
    result = {"status": "COMPLETE", "rows": [dict(peer="Coaptic-Mio", case=case,
              round=i, result={"exit_code": 0, "sample": copy.deepcopy(sample)}) for i in range(3)]}
    return method, result


class HostTests(unittest.TestCase):
    def test_runtime_identity_follows_selector_not_display_label(self):
        method, result = fixture()
        method["peers"][0]["server"][1] = "coaptic-reusable"
        with self.assertRaises(ValueError):
            report.host_summary(method, result)
        self.assertEqual(report.execution_policy({"id": "libcoap", "server": ["unknown"]})[1], "unknown")
    def test_complete_cell_recomputed_without_trusting_saved_summary(self):
        method, result = fixture()
        result["summary"] = [{"median_goodput": 999999}]
        cell = report.host_summary(method, result)["cells"][0]
        self.assertTrue(cell["eligible"])
        self.assertEqual(cell["ops_s"], 20_000_000)
        self.assertEqual(cell["median_us"], .015)

    def test_one_failed_round_disables_whole_cell_no_success_filter(self):
        method, result = fixture()
        sample = result["rows"][1]["result"]["sample"]
        sample.update(completed=1, failed=1, latencies_ns=[10], verified_bytes=64)
        cell = report.host_summary(method, result)["cells"][0]
        self.assertFalse(cell["eligible"])
        self.assertEqual(cell["failed_rounds"], 1)
        self.assertIsNone(cell["ops_s"])
        self.assertEqual(cell["process_ops_s"], [])

    def test_missing_round_and_failed_campaign_disable_metrics(self):
        method, result = fixture()
        result["rows"].pop()
        cell = report.host_summary(method, result)["cells"][0]
        self.assertEqual(cell["missing_rounds"], 1)
        self.assertIsNone(cell["ops_s"])
        method, result = fixture()
        result["status"] = "FAILED"
        self.assertIsNone(report.host_summary(method, result)["cells"][0]["ops_s"])

    def test_duplicate_unplanned_and_cross_mode_evidence_refused(self):
        for mutate in (lambda x: x["rows"].append(copy.deepcopy(x["rows"][0])),
                       lambda x: x["rows"][0].update(peer="another"),
                       lambda x: x["rows"][0]["result"]["sample"].update(security="oscore")):
            method, result = fixture()
            mutate(result)
            with self.assertRaises(ValueError):
                report.host_summary(method, result)

    def test_warmup_failure_and_nonzero_exit_ineligible(self):
        for exit_code in (1, 101):
            method, result = fixture()
            result["rows"][0]["result"]["exit_code"] = exit_code
            self.assertFalse(report.host_summary(method, result)["cells"][0]["eligible"])
        method, result = fixture()
        method["cases"][0]["warmup"] = 1
        for row in result["rows"]:
            row["result"]["sample"]["warmup"] = 1
        result["rows"][1]["result"]["sample"]["warmup_failed"] = 1
        self.assertFalse(report.host_summary(method, result)["cells"][0]["eligible"])

    def test_malformed_counts_and_nonfinite_resources_refused(self):
        method, result = fixture()
        result["rows"][0]["result"]["sample"]["completed"] = True
        with self.assertRaises(ValueError):
            report.host_summary(method, result)
        method, result = fixture()
        for row in result["rows"]:
            row["result"]["startup_first_verified_response_ms"] = float("nan")
        with self.assertRaises(ValueError):
            report.host_summary(method, result)

    def test_resource_ledgers_not_added_to_process_memory(self):
        method, result = fixture()
        for row in result["rows"]:
            row["result"].update(idle={"memory": {"private": 100}},
                                 server_stdout='{"schema":"coaptic-native-mio-resources/1","app_bytes":1000}')
        cell = report.host_summary(method, result)["cells"][0]
        self.assertEqual(cell["idle_private_bytes"], 100)
        self.assertEqual(len(cell["resource_ledgers"]), 1)


class InputTests(unittest.TestCase):
    def test_json_duplicate_nonfinite_and_oversize_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            for raw in ('{"x":1,"x":2}', '{"x":NaN}'):
                path.write_text(raw)
                with self.assertRaises(ValueError):
                    report.load(path)

    def test_html_cannot_execute_evidence_labels(self):
        document = report.render({"host": {"cells": []}, "loc": [], "sources": [],
                                  "label": "</script><script>alert(1)</script>"})
        self.assertNotIn("</script><script>", document)
        self.assertIn("\\u003c/script>", document)

    def test_loc_test_subset_must_conserve(self):
        totals = dict(files=2, code=10, comment=3, blank=2)
        tests = dict(files=1, code=4, comment=1, blank=1)
        other = dict(files=1, code=6, comment=2, blank=1)
        group = dict(totals=totals, recognized_test_files=tests,
                     other_files_including_inline_tests=other, scope="test", notes=[])
        value = {"schema": "coaptic-scoped-loc/1", "groups": {name: copy.deepcopy(group)
                 for name in ("coaptic", "coap-rs", "libcoap", "go-coap", "aiocoap")}}
        rows = report.loc_summary(value)
        self.assertEqual(rows[0]["dedicated_tests"], 4)
        value["groups"]["coaptic"]["totals"]["code"] = 9
        with self.assertRaises(ValueError):
            report.loc_summary(value)


def device_fixture(root):
    value = dict(schema="coaptic-esp-server-comparison/1", status="complete",
                 measurements_passed=True, passed=True, restore_verified=True,
                 method={"security": "unprotected"}, cohorts=[])
    for index, mode in enumerate(("sync", "async", "libcoap-native")):
        cohort = dict(name=mode, device_mode=mode, passed=True, clients=[])
        value["cohorts"].append(cohort)
        for ordinal, client in enumerate(("sync", "async", "async", "sync"), 1):
            name = f"{mode}-round-{ordinal}-windows-{client}.jsonl"
            operations = [dict(case="complete_operation", passed=True, iteration=i,
                path=p, bytes=b, elapsed_ns=1000 + index * 100 + ordinal,
                poll_ns=100, sleep_ns=800, recv_ns=40, send_ns=40)
                for i in range(8) for p, b in (("identity", 32), ("test", 7), ("large", 2000))]
            raw = "\n".join(json.dumps(o) for o in operations).encode()
            (root / name).write_bytes(raw)
            cohort["clients"].append(dict(mode=client, ordinal=ordinal, passed=True,
                operations=24, report_path=name, source_report_sha256=hashlib.sha256(raw).hexdigest()))
    return value


class DeviceTests(unittest.TestCase):
    def run_fixture(self, change=lambda value: None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = device_fixture(root)
            change(value)
            path = root / "result.json"
            path.write_text(json.dumps(value))
            return report.device_summary(path)

    def test_complete_raw_recomputation(self):
        result = self.run_fixture()
        self.assertTrue(result["eligible"])
        self.assertEqual(result["operations"], 288)
        self.assertEqual(len(result["rows"]), 18)
        self.assertTrue(all(r["n"] == 16 for r in result["rows"]))

    def test_failed_top_level_cannot_display_normal_metrics(self):
        for changes in ({"status": "failed"}, {"measurements_passed": False}):
            result = self.run_fixture(lambda value: value.update(changes))
            self.assertFalse(result["eligible"])
            self.assertTrue(all(r["mean_ms"] is None for r in result["rows"]))

    def test_restoration_failure_separate_and_visible(self):
        result = self.run_fixture(lambda value: value.update(restore_verified=False, passed=False))
        self.assertTrue(result["eligible"])
        self.assertFalse(result["restored"])
        self.assertFalse(result["passed"])
        self.assertIn("restoration is NOT verified", report.render({}))

    def test_reused_process_and_cross_mode_binding_refuse(self):
        def alias(value):
            first = value["cohorts"][0]["clients"][0]
            for cohort in value["cohorts"]:
                for client in cohort["clients"]:
                    client.update(report_path=first["report_path"],
                                  source_report_sha256=first["source_report_sha256"])
        with self.assertRaises(ValueError):
            self.run_fixture(alias)
        with self.assertRaises(ValueError):
            self.run_fixture(lambda value: value["cohorts"][0]["clients"][1].update(mode="sync"))

    def test_corrupt_hash_and_missing_process_refuse(self):
        with self.assertRaises(ValueError):
            self.run_fixture(lambda value: value["cohorts"][0]["clients"][0].update(source_report_sha256="0" * 64))
        with self.assertRaises(ValueError):
            self.run_fixture(lambda value: value["cohorts"][0]["clients"].pop())


if __name__ == "__main__":
    unittest.main()
