"""Focused counterexamples for the portable privacy and measurement boundary."""
from pathlib import Path
import copy
import gzip
import importlib.util
import json
import unittest

ROOT = Path(__file__).resolve().parent

def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

exporter, verifier = module("export"), module("verify")

class ExportBoundary(unittest.TestCase):
    def small(self):
        return {"operations": 8, "security": "unprotected", "payload_bytes": 32, "black_box": True, "dedup": 4, "latencies_cycles": list(range(10, 18)), "operator_path": "C:/Users/private/state", "credential": "PRIVATE_SENTINEL"}

    def test_exact_cpu_sum_keeps_every_operation(self):
        result = exporter.cpu_sample(self.small(), ["ordinary", "small-device", "unprotected", "sync", 32], 8)
        self.assertEqual((result["cycles_sum"], result["cycles_count"], result["cycles_min"], result["cycles_max"]), (108, 8, 10, 17))

    def test_unknown_private_cpu_fields_are_not_exported(self):
        raw = exporter.encoded(exporter.cpu_sample(self.small(), ["ordinary", "small-device", "unprotected", "sync", 32], 8))
        self.assertNotIn(b"PRIVATE_SENTINEL", raw)
        self.assertNotIn(b"Users", raw)

    def test_nonpositive_cpu_counter_is_refused(self):
        raw = self.small()
        raw["latencies_cycles"][-1] = 0
        with self.assertRaises(AssertionError):
            exporter.cpu_sample(raw, ["ordinary", "small-device", "unprotected", "sync", 32], 8)

    def test_wifi_latency_whitelist_drops_identity_and_private_fields(self):
        raw = {"passed": True, "iteration": 0, "path": "test", "bytes": 7, "elapsed_ns": 100, "prepare_ns": 1, "poll_ns": 20, "checkpoint_ns": 0, "take_ns": 0, "verify_ns": 1, "sleep_ns": 0, "events": [[2, 3, 4, 5, 6]], "run_id": "PRIVATE_SENTINEL", "operator_path": "C:/Users/private"}
        result = exporter.wifi_operation(raw)
        self.assertEqual(result["request_send_ids"], [6])
        self.assertNotIn(b"PRIVATE_SENTINEL", exporter.encoded(result))
        self.assertNotIn("operator_path", result)

    def test_public_urls_are_allowed_and_private_paths_addresses_refused(self):
        self.assertFalse(exporter.forbidden(b'https://github.com/jeffglousher/coaptic'))
        for text in [b'C:/Users/private/state', b'D:\\private\\state', b'192.168.', b'noise_psk', b't3-thread://private']:
            self.assertTrue(exporter.forbidden(text))

    def test_source_input_traversal_is_refused(self):
        values = {"coaptic/f" + str(i) + ".rs": "a" * 64 for i in range(180)}
        values["../outside.rs"] = "a" * 64
        with self.assertRaises(AssertionError):
            exporter.input_map(values)

    def test_source_input_absolute_path_is_refused(self):
        values = {"coaptic/f" + str(i) + ".rs": "a" * 64 for i in range(180)}
        values["/outside.rs"] = "a" * 64
        with self.assertRaises(AssertionError):
            exporter.input_map(values)

    def test_preflight_whitelist_omits_private_commands_and_logs(self):
        value = {"baseline": "a" * 40, "candidate": "b" * 40, "argv": ["PRIVATE_SENTINEL"], "rows": [{"arm": "A", "bytes": 20, "log": "PRIVATE_SENTINEL", "log_sha256": "c" * 64}]}
        raw = exporter.encoded(exporter.preflight_fields(value))
        self.assertNotIn(b"PRIVATE_SENTINEL", raw)
        self.assertIn(b'"bytes":20', raw)

    def test_altered_fixture_source_is_refused(self):
        with gzip.open(ROOT / "sources/host-inputs.json.gz", "rt", encoding="utf-8") as stream:
            inputs = json.load(stream)
        with gzip.open(ROOT / "sources/request-context-fixture.json.gz", "rt", encoding="utf-8") as stream:
            fixture = json.load(stream)
        next(iter(fixture["files"].values()))["text"] += "changed"
        cpu = [{"name": row["name"], "candidate": row["candidate"]} for row in inputs["cohorts"]]
        with self.assertRaises(AssertionError):
            verifier.verify_sources(inputs, fixture, cpu)

    def data(self):
        with gzip.open(ROOT / "cpu/body-inspection.json.gz", "rt", encoding="utf-8") as stream:
            return json.load(stream)

    def test_missing_process_cannot_be_hidden(self):
        data = self.data()
        data["records"].pop()
        with self.assertRaises(AssertionError):
            verifier.verify_cpu(data)

    def test_altered_sufficient_statistic_is_refused(self):
        data = self.data()
        data["records"][0]["cycles_sum"] = 0
        with self.assertRaises(AssertionError):
            verifier.verify_cpu(data)

    def test_claimed_acceptance_cannot_override_actual_failed_bounds(self):
        data = self.data()
        data["expected"]["runtime_accepted"] = True
        with self.assertRaises(AssertionError):
            verifier.verify_cpu(data)

if __name__ == "__main__":
    unittest.main()
